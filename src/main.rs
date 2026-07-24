use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ghostline_red::{archive, codec, cr2w, kraken, localization, schema, writer};
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Path to `WolvenKit`'s compatible Kraken compression library.
    #[arg(long, global = true, default_value = "kraken.dll")]
    kraken: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(hide = true)]
    KrakenCompressWorker,
    #[command(hide = true)]
    KrakenDecompressWorker,
    /// Encode a DLL-free Kraken stream (raw blocks, with constant-block compression).
    KrakenEncode {
        input: PathBuf,
        output: PathBuf,
        /// Prefer the crash-isolated native compressor for differential diagnosis.
        #[arg(long)]
        native: bool,
    },
    /// Decode a DLL-free Kraken stream supported by the clean-room backend.
    KrakenDecode {
        input: PathBuf,
        output: PathBuf,
        /// Exact number of uncompressed bytes expected.
        #[arg(long)]
        size: usize,
        /// Fall back to the crash-isolated native library when clean decoding is unsupported.
        #[arg(long)]
        native_fallback: bool,
    },
    /// Pack a loose depot tree into an archive.
    Pack {
        source: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Extract every payload using embedded depot paths.
    Extract {
        archive: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Extract only this exact depot path (`WolvenKit` `-w` equivalent).
        #[arg(short = 'w', long)]
        path: Option<String>,
        /// Resolve native hashes from files beneath this depot root.
        #[arg(long)]
        paths_root: Option<PathBuf>,
    },
    /// Read a Cyberpunk archive index without extracting payloads.
    ArchiveList {
        archive: PathBuf,
        /// Resolve hashes from files beneath this depot root (for example source/archive).
        #[arg(long)]
        paths_root: Option<PathBuf>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a CR2W header and its ten table descriptors.
    Cr2wInspect {
        input: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Decode reflected CR2W exports with a generated RED schema.
    Cr2wDecode {
        input: PathBuf,
        #[arg(long)]
        schema: PathBuf,
        output: PathBuf,
    },
    /// Serialize CR2W to recursive WKit-shaped JSON.
    Cr2wSerialize {
        input: PathBuf,
        #[arg(long)]
        schema: PathBuf,
        output: PathBuf,
    },
    /// Deserialize WKit-shaped JSON using an existing CR2W table/layout template.
    Cr2wDeserialize {
        input: PathBuf,
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        schema: PathBuf,
        output: PathBuf,
    },
    /// Serialize supported onscreen localization CR2W to WolvenKit-shaped JSON.
    Cr2wSerializeLocalization { input: PathBuf, output: PathBuf },
    /// Deserialize onscreen localization JSON using a CR2W type-table template.
    Cr2wDeserializeLocalization {
        input: PathBuf,
        #[arg(long)]
        template: PathBuf,
        output: PathBuf,
    },
    /// Generate compact RED class/property metadata from `WolvenKit` source.
    SchemaGenerate { wolvenkit: PathBuf, output: PathBuf },
}

#[expect(
    clippy::too_many_lines,
    reason = "the CLI dispatcher keeps each command's small output contract visible"
)]
fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::KrakenCompressWorker => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input)?;
            let output = archive::compress_worker_batch(&input, cli.kraken.as_os_str())?;
            std::io::stdout().write_all(&output)?;
        }
        Command::KrakenDecompressWorker => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input)?;
            let output = archive::decompress_worker(&input, cli.kraken.as_os_str())?;
            std::io::stdout().write_all(&output)?;
        }
        Command::KrakenEncode {
            input,
            output,
            native,
        } => {
            let decoded =
                fs::read(&input).with_context(|| format!("failed to read {}", input.display()))?;
            let encoded = if native {
                archive::compress_payload_isolated(&decoded, cli.kraken.as_os_str())
            } else {
                kraken::encode(&decoded)
            };
            fs::write(&output, encoded)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
        Command::KrakenDecode {
            input,
            output,
            size,
            native_fallback,
        } => {
            let encoded =
                fs::read(&input).with_context(|| format!("failed to read {}", input.display()))?;
            let decoded = if native_fallback {
                archive::decompress_payload_isolated(&encoded, size, cli.kraken.as_os_str())
                    .with_context(|| format!("failed to decode {}", input.display()))?
            } else {
                kraken::decode(&encoded, size)
                    .with_context(|| format!("failed to decode {}", input.display()))?
            };
            fs::write(&output, decoded)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
        Command::Pack { source, output } => {
            fs::create_dir_all(&output)?;
            let name = source
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("archive");
            let candidate = output.join(format!("{name}.archive"));
            archive::pack(&source, &candidate, cli.kraken.as_os_str())?;
            println!("{}", candidate.display());
        }
        Command::Extract {
            archive: path,
            output,
            path: depot_path,
            paths_root,
        } => {
            fs::create_dir_all(&output)?;
            if let Some(depot_path) = depot_path {
                archive::extract_path(&path, &output, &depot_path, cli.kraken.as_os_str())?;
            } else {
                archive::extract(
                    &path,
                    &output,
                    cli.kraken.as_os_str(),
                    paths_root.as_deref(),
                )?;
            }
        }
        Command::ArchiveList {
            archive: path,
            paths_root,
            json,
        } => {
            let mut index = archive::read_archive(&path)
                .with_context(|| format!("failed to inspect {}", path.display()))?;
            if index.custom_paths.is_empty() {
                index.custom_paths = archive::read_archive_paths(&path, cli.kraken.as_os_str())?;
            }
            let names = paths_root
                .as_deref()
                .map(load_depot_paths)
                .transpose()?
                .unwrap_or_default();
            if json {
                serde_json::to_writer_pretty(std::io::stdout(), &index)?;
                println!();
            } else {
                println!(
                    "{}: version {}, {} files, {} segments",
                    path.display(),
                    index.header.version,
                    index.entries.len(),
                    index.segment_count
                );
                println!("HASH              SIZE       PACKED     SEGMENTS  PATH");
                for entry in index.entries {
                    println!(
                        "{:016x}  {:>10} {:>10}  {}..{}  {}",
                        entry.name_hash,
                        entry.size,
                        entry.compressed_size,
                        entry.segments_start,
                        entry.segments_end,
                        names
                            .get(&entry.name_hash)
                            .map_or("<unresolved>", String::as_str)
                    );
                }
            }
        }
        Command::Cr2wInspect { input, json } => {
            let header = cr2w::inspect(&input)
                .with_context(|| format!("failed to inspect {}", input.display()))?;
            if json {
                serde_json::to_writer_pretty(std::io::stdout(), &header)?;
                println!();
            } else {
                println!(
                    "{}: CR2W v{}, build {}, {} chunks",
                    input.display(),
                    header.header.version,
                    header.header.build_version,
                    header.header.chunk_count
                );
                println!(
                    "{} strings, {} names, {} imports, {} exports, {} buffers",
                    header.strings.len(),
                    header.names.len(),
                    header.imports.len(),
                    header.exports.len(),
                    header.buffers.len()
                );
                for (index, table) in header.header.tables.iter().enumerate() {
                    println!(
                        "table {index}: offset={:#x}, items={}, crc={:#010x}",
                        table.offset, table.item_count, table.crc32
                    );
                }
            }
        }
        Command::Cr2wDecode {
            input,
            schema,
            output,
        } => {
            let classes: HashMap<String, schema::RedClass> =
                serde_json::from_slice(&fs::read(schema)?)?;
            let class_names: BTreeSet<String> = classes.into_keys().collect();
            let document = codec::decode_exports(&input, &class_names, cli.kraken.as_os_str())?;
            fs::write(output, serde_json::to_vec_pretty(&document)?)?;
        }
        Command::Cr2wSerialize {
            input,
            schema,
            output,
        } => {
            let classes: HashMap<String, schema::RedClass> =
                serde_json::from_slice(&fs::read(schema)?)?;
            let class_names: BTreeSet<String> = classes.into_keys().collect();
            let document = codec::decode_wkit(&input, &class_names, cli.kraken.as_os_str())?;
            fs::write(output, serde_json::to_vec_pretty(&document)?)?;
        }
        Command::Cr2wDeserialize {
            input,
            template,
            schema,
            output,
        } => {
            let classes: HashMap<String, schema::RedClass> =
                serde_json::from_slice(&fs::read(schema)?)?;
            let class_names: BTreeSet<String> = classes.into_keys().collect();
            writer::write_with_template(
                &input,
                &template,
                &output,
                &class_names,
                cli.kraken.as_os_str(),
            )?;
        }
        Command::Cr2wSerializeLocalization { input, output } => {
            localization::write_json(&input, &output)?;
        }
        Command::Cr2wDeserializeLocalization {
            input,
            template,
            output,
        } => {
            localization::write_from_json(&input, &template, &output)?;
        }
        Command::SchemaGenerate { wolvenkit, output } => {
            let count = schema::generate(&wolvenkit, &output)?;
            println!("wrote {count} RED classes to {}", output.display());
        }
    }
    Ok(())
}

fn load_depot_paths(root: &Path) -> Result<HashMap<u64, String>> {
    let mut result = HashMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for item in fs::read_dir(&directory)
            .with_context(|| format!("failed to read path root {}", directory.display()))?
        {
            let path = item?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .with_context(|| format!("{} is outside {}", path.display(), root.display()))?;
            let depot_path = relative.to_string_lossy().replace('/', "\\");
            result.insert(archive::depot_path_hash(&depot_path), depot_path);
        }
    }
    Ok(result)
}

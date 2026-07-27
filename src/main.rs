use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ghostline_red::{
    archive, codec, cr2w, kraken, localization, material, mesh, pbr, schema, writer,
};
use rayon::{ThreadPoolBuilder, prelude::*};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
use tempfile::NamedTempFile;

#[derive(Debug, Deserialize)]
struct MeshExportBatchManifest {
    jobs: Vec<MeshExportBatchJob>,
}

#[derive(Debug, Deserialize)]
struct MeshExportBatchJob {
    mesh: String,
    appearance: String,
    output: PathBuf,
}

#[derive(Debug, Serialize)]
struct MeshExportBatchOutcome {
    mesh: String,
    appearance: String,
    output: PathBuf,
    error: Option<String>,
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Optional Kraken library used only by explicit native diagnostic flags.
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
    /// Encode a DLL-free Kraken stream with entropy and LZ compression.
    KrakenEncode {
        input: PathBuf,
        output: PathBuf,
        /// Prefer the crash-isolated native compressor for differential diagnosis.
        #[arg(long)]
        native: bool,
    },
    /// Decode a Kraken stream with the clean-room backend.
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
        /// Schema sources in increasing precedence order.
        #[arg(long, required = true)]
        schema: Vec<PathBuf>,
        output: PathBuf,
    },
    /// Serialize CR2W to recursive WKit-shaped JSON.
    Cr2wSerialize {
        input: PathBuf,
        /// Schema sources in increasing precedence order.
        #[arg(long, required = true)]
        schema: Vec<PathBuf>,
        output: PathBuf,
    },
    /// Deserialize WKit-shaped JSON using an existing CR2W table/layout template.
    Cr2wDeserialize {
        input: PathBuf,
        #[arg(long)]
        template: PathBuf,
        /// Schema sources in increasing precedence order.
        #[arg(long, required = true)]
        schema: Vec<PathBuf>,
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
    /// Export a Cyberpunk mesh to a WolvenKit-compatible binary glTF.
    MeshExport {
        input: PathBuf,
        /// Schema sources in increasing precedence order.
        #[arg(long, required = true)]
        schema: Vec<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        /// Include every LOD instead of only the first render LOD.
        #[arg(long)]
        all_lods: bool,
        /// Index game archives and export the mesh's complete material dependency graph.
        #[arg(long, requires = "material_repo")]
        archives_root: Option<PathBuf>,
        /// Destination for uncooked textures, masks, and material documents.
        #[arg(long, requires = "archives_root")]
        material_repo: Option<PathBuf>,
        /// Export only the materials needed by this mesh appearance.
        #[arg(long, requires = "archives_root")]
        appearance: Option<String>,
        /// Bake selected Cyberpunk materials to standard glTF PBR textures.
        #[arg(long, requires = "appearance")]
        pbr: bool,
        /// Square resolution for generated PBR textures.
        #[arg(long, default_value_t = 512)]
        pbr_size: u32,
    },
    /// Export many archive-backed mesh appearances while indexing archives once.
    MeshExportBatch {
        manifest: PathBuf,
        /// Schema sources in increasing precedence order.
        #[arg(long, required = true)]
        schema: Vec<PathBuf>,
        /// Root containing the game's content, expansion, hotfix, and mod archives.
        #[arg(long)]
        archives_root: PathBuf,
        /// Shared destination for decoded material dependencies.
        #[arg(long)]
        material_repo: PathBuf,
        /// Machine-readable per-job outcome report.
        #[arg(long)]
        report: PathBuf,
        /// Bake every selected material to standard glTF PBR textures.
        #[arg(long)]
        pbr: bool,
        /// Square resolution for generated PBR textures.
        #[arg(long, default_value_t = 512)]
        pbr_size: u32,
        /// Concurrent export jobs; zero uses all available logical CPUs.
        #[arg(long, default_value_t = 0)]
        threads: usize,
    },
    /// Attach standard glTF PBR materials to an existing exported mesh.
    PbrBake {
        glb: PathBuf,
        #[arg(long)]
        sidecar: PathBuf,
        #[arg(long)]
        appearance: String,
        #[arg(long, default_value_t = 512)]
        size: u32,
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
                archive::compress_payload_native_worker(&decoded, cli.kraken.as_os_str())
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
                archive::decompress_payload_native_fallback(&encoded, size, cli.kraken.as_os_str())
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
            let schema = load_schemas(&schema)?;
            let document =
                codec::decode_exports_with_red_schema(&input, &schema, cli.kraken.as_os_str())?;
            fs::write(output, serde_json::to_vec_pretty(&document)?)?;
        }
        Command::Cr2wSerialize {
            input,
            schema,
            output,
        } => {
            let schema = load_schemas(&schema)?;
            let document =
                codec::decode_wkit_with_red_schema(&input, &schema, cli.kraken.as_os_str())?;
            fs::write(output, serde_json::to_vec_pretty(&document)?)?;
        }
        Command::Cr2wDeserialize {
            input,
            template,
            schema,
            output,
        } => {
            let schema = load_schemas(&schema)?;
            writer::write_with_red_schema(
                &input,
                &template,
                &output,
                &schema,
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
        Command::MeshExport {
            input,
            schema,
            output,
            all_lods,
            archives_root,
            material_repo,
            appearance,
            pbr,
            pbr_size,
        } => {
            let schema = load_schemas(&schema)?;
            mesh::export_glb(&input, &schema, &output, cli.kraken.as_os_str(), !all_lods)?;
            if let (Some(archives_root), Some(material_repo)) = (archives_root, material_repo) {
                let archives = material::ArchiveSet::open(&archives_root)?;
                let sidecar = output.with_extension("Material.json");
                let summary = material::export_mesh_materials(
                    &input,
                    &schema,
                    &archives,
                    &material_repo,
                    &sidecar,
                    cli.kraken.as_os_str(),
                    appearance.as_deref(),
                )?;
                eprintln!(
                    "{} materials, {} dependencies ({} textures, {} masks)",
                    summary.materials, summary.dependencies, summary.textures, summary.masks
                );
                if pbr {
                    let appearance = appearance
                        .as_deref()
                        .context("--pbr requires an explicit --appearance")?;
                    let summary =
                        pbr::bake_sidecar_into_glb(&sidecar, &output, appearance, Some(pbr_size))?;
                    eprintln!(
                        "{} PBR materials ({} generated textures, {} reused)",
                        summary.materials, summary.generated_textures, summary.reused_textures
                    );
                }
            }
            println!("{}", output.display());
        }
        Command::MeshExportBatch {
            manifest,
            schema,
            archives_root,
            material_repo,
            report,
            pbr,
            pbr_size,
            threads,
        } => {
            let schema = load_schemas(&schema)?;
            let manifest: MeshExportBatchManifest = serde_json::from_slice(&fs::read(&manifest)?)?;
            let archives = material::ArchiveSet::open(&archives_root)?;
            let job_count = manifest.jobs.len();
            let thread_count = if threads == 0 {
                std::thread::available_parallelism().map_or(1, usize::from)
            } else {
                threads
            };
            eprintln!("exporting {job_count} jobs with {thread_count} threads");
            let pool = ThreadPoolBuilder::new().num_threads(thread_count).build()?;
            let completed = AtomicUsize::new(0);
            let outcomes = pool.install(|| {
                manifest
                    .jobs
                    .into_par_iter()
                    .map(|job| {
                        let result = (|| -> Result<()> {
                            let bytes =
                                archives.read_resource(&job.mesh, cli.kraken.as_os_str())?;
                            let mut input = NamedTempFile::new()?;
                            input.write_all(&bytes)?;
                            mesh::export_glb(
                                input.path(),
                                &schema,
                                &job.output,
                                cli.kraken.as_os_str(),
                                true,
                            )?;
                            let sidecar = job.output.with_extension("Material.json");
                            material::export_mesh_materials(
                                input.path(),
                                &schema,
                                &archives,
                                &material_repo,
                                &sidecar,
                                cli.kraken.as_os_str(),
                                Some(&job.appearance),
                            )?;
                            if pbr {
                                pbr::bake_sidecar_into_glb(
                                    &sidecar,
                                    &job.output,
                                    &job.appearance,
                                    Some(pbr_size),
                                )?;
                            }
                            Ok(())
                        })();
                        let position = completed.fetch_add(1, Ordering::Relaxed) + 1;
                        eprintln!("[{position}/{job_count}] {} ({})", job.mesh, job.appearance);
                        MeshExportBatchOutcome {
                            mesh: job.mesh,
                            appearance: job.appearance,
                            output: job.output,
                            error: result.err().map(|error| format!("{error:#}")),
                        }
                    })
                    .collect::<Vec<_>>()
            });
            if let Some(parent) = report.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&report, serde_json::to_vec_pretty(&outcomes)?)?;
            let failures = outcomes
                .iter()
                .filter(|outcome| outcome.error.is_some())
                .count();
            println!(
                "completed {} mesh exports with {failures} failures",
                outcomes.len()
            );
            if failures > 0 {
                anyhow::bail!(
                    "{failures} mesh export jobs failed; see {}",
                    report.display()
                );
            }
        }
        Command::PbrBake {
            glb,
            sidecar,
            appearance,
            size,
        } => {
            let summary = pbr::bake_sidecar_into_glb(&sidecar, &glb, &appearance, Some(size))?;
            println!(
                "{} PBR materials ({} generated textures, {} reused)",
                summary.materials, summary.generated_textures, summary.reused_textures
            );
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

fn load_schemas(paths: &[PathBuf]) -> Result<schema::RedSchema> {
    let mut result = schema::RedSchema::default();
    for path in paths {
        result.merge(
            schema::RedSchema::from_slice(
                &fs::read(path)
                    .with_context(|| format!("failed to read schema {}", path.display()))?,
            )
            .with_context(|| format!("failed to parse schema {}", path.display()))?,
        );
    }
    Ok(result)
}

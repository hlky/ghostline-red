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
#[serde(deny_unknown_fields)]
struct MeshExportBatchManifest {
    jobs: Vec<MeshExportBatchJob>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeshExportBatchJob {
    mesh: String,
    #[serde(default)]
    appearance: Option<String>,
    output: PathBuf,
}

#[derive(Debug, Serialize)]
struct MeshExportBatchOutcome {
    mesh: String,
    appearance: Option<String>,
    output: PathBuf,
    error: Option<String>,
    material_error: Option<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MeshExportBatchErrors {
    error: Option<String>,
    material_error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cr2wSerializeBatchManifest {
    jobs: Vec<Cr2wSerializeBatchJob>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Cr2wSerializeBatchJob {
    resource: String,
    output: PathBuf,
}

#[derive(Debug, Serialize)]
struct Cr2wSerializeBatchOutcome {
    resource: String,
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
    /// Serialize many archive-backed CR2W resources while indexing archives once.
    Cr2wSerializeBatch {
        manifest: PathBuf,
        /// Schema sources in increasing precedence order.
        #[arg(long, required = true)]
        schema: Vec<PathBuf>,
        /// Root containing the game's content, expansion, hotfix, and mod archives.
        #[arg(long)]
        archives_root: PathBuf,
        /// Machine-readable per-job outcome report.
        #[arg(long)]
        report: PathBuf,
        /// Concurrent serialization jobs; zero uses all available logical CPUs.
        #[arg(long, default_value_t = 0)]
        threads: usize,
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
        Command::Cr2wSerializeBatch {
            manifest,
            schema,
            archives_root,
            report,
            threads,
        } => {
            let schema = load_schemas(&schema)?;
            let manifest: Cr2wSerializeBatchManifest = serde_json::from_slice(
                &fs::read(&manifest)
                    .with_context(|| format!("failed to read manifest {}", manifest.display()))?,
            )
            .with_context(|| format!("failed to parse manifest {}", manifest.display()))?;
            let archives = material::ArchiveSet::open(&archives_root)?;
            let job_count = manifest.jobs.len();
            let thread_count = if threads == 0 {
                std::thread::available_parallelism().map_or(1, usize::from)
            } else {
                threads
            };
            eprintln!("serializing {job_count} CR2W resources with {thread_count} threads");
            let pool = ThreadPoolBuilder::new().num_threads(thread_count).build()?;
            let completed = AtomicUsize::new(0);
            let outcomes = pool.install(|| {
                manifest
                    .jobs
                    .into_par_iter()
                    .map(|job| {
                        let result = serialize_archive_resource(
                            &job,
                            &schema,
                            &archives,
                            cli.kraken.as_os_str(),
                        );
                        let position = completed.fetch_add(1, Ordering::Relaxed) + 1;
                        eprintln!("[{position}/{job_count}] {}", job.resource);
                        Cr2wSerializeBatchOutcome {
                            resource: job.resource,
                            output: job.output,
                            error: result.err().map(|error| format!("{error:#}")),
                        }
                    })
                    .collect::<Vec<_>>()
            });
            write_json_atomic(&report, &outcomes)?;
            let failures = outcomes
                .iter()
                .filter(|outcome| outcome.error.is_some())
                .count();
            println!(
                "completed {} CR2W serializations with {failures} failures",
                outcomes.len()
            );
            if failures > 0 {
                anyhow::bail!(
                    "{failures} CR2W serialization jobs failed; see {}",
                    report.display()
                );
            }
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
            validate_mesh_export_batch_outputs(&manifest.jobs)?;
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
            let fatal_completed = AtomicUsize::new(0);
            let material_warnings_completed = AtomicUsize::new(0);
            let outcomes = pool.install(|| {
                manifest
                    .jobs
                    .into_par_iter()
                    .map(|job| {
                        let errors = run_mesh_export_batch_job(
                            &job,
                            &schema,
                            &archives,
                            &material_repo,
                            cli.kraken.as_os_str(),
                            pbr,
                            pbr_size,
                        );
                        let is_fatal = errors.error.is_some();
                        let has_material_warning = errors.material_error.is_some();
                        let fatal_count = if is_fatal {
                            fatal_completed.fetch_add(1, Ordering::Relaxed) + 1
                        } else {
                            fatal_completed.load(Ordering::Relaxed)
                        };
                        let material_warning_count = if has_material_warning {
                            material_warnings_completed.fetch_add(1, Ordering::Relaxed) + 1
                        } else {
                            material_warnings_completed.load(Ordering::Relaxed)
                        };
                        let position = completed.fetch_add(1, Ordering::Relaxed) + 1;
                        let is_first_problem = (is_fatal && fatal_count == 1)
                            || (has_material_warning && material_warning_count == 1);
                        if should_report_batch_progress(position, job_count) || is_first_problem {
                            let appearance = job.appearance.as_deref().unwrap_or("all appearances");
                            let status = match (is_fatal, has_material_warning) {
                                (true, _) => "failed",
                                (false, true) => "material warning",
                                (false, false) => "complete",
                            };
                            eprintln!(
                                "[{position}/{job_count}] {status}: {} ({appearance}); \
                                 {fatal_count} fatal, {material_warning_count} material warnings",
                                job.mesh
                            );
                        }
                        MeshExportBatchOutcome {
                            mesh: job.mesh,
                            appearance: job.appearance,
                            output: job.output,
                            error: errors.error,
                            material_error: errors.material_error,
                        }
                    })
                    .collect::<Vec<_>>()
            });
            write_json_atomic(&report, &outcomes)?;
            let (failures, material_warnings) = mesh_export_batch_outcome_counts(&outcomes);
            println!(
                "completed {} mesh exports with {failures} failures and {material_warnings} \
                 material warnings",
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

fn run_mesh_export_batch_job(
    job: &MeshExportBatchJob,
    schema: &schema::RedSchema,
    archives: &material::ArchiveSet,
    material_repo: &Path,
    kraken_path: &std::ffi::OsStr,
    pbr: bool,
    pbr_size: u32,
) -> MeshExportBatchErrors {
    let geometry = (|| -> Result<NamedTempFile> {
        let bytes = archives
            .read_resource(&job.mesh, kraken_path)
            .with_context(|| format!("failed to read archive mesh {}", job.mesh))?;
        let mut input = NamedTempFile::new()
            .with_context(|| format!("failed to create temporary input for {}", job.mesh))?;
        input
            .write_all(&bytes)
            .with_context(|| format!("failed to stage archive mesh {}", job.mesh))?;
        mesh::export_glb(input.path(), schema, &job.output, kraken_path, true)
            .with_context(|| format!("failed to export GLB for {}", job.mesh))?;
        Ok(input)
    })();
    let input = match geometry {
        Ok(input) => input,
        Err(error) => return fatal_mesh_export_error(&error),
    };

    let sidecar = job.output.with_extension("Material.json");
    let material_result = (|| -> Result<()> {
        material::export_mesh_materials(
            input.path(),
            schema,
            archives,
            material_repo,
            &sidecar,
            kraken_path,
            job.appearance.as_deref(),
        )
        .with_context(|| format!("failed to export material sidecar for {}", job.mesh))?;
        Ok(())
    })();
    if let Err(error) = material_result {
        return classify_material_export_error(&error, &sidecar, pbr);
    }

    if pbr {
        let bake_result = (|| -> Result<()> {
            let appearance = job
                .appearance
                .as_deref()
                .context("batch --pbr requires an explicit appearance")?;
            pbr::bake_sidecar_into_glb(&sidecar, &job.output, appearance, Some(pbr_size))
                .with_context(|| format!("failed to bake PBR materials for {}", job.mesh))?;
            Ok(())
        })();
        if let Err(error) = bake_result {
            return fatal_mesh_export_error(&error);
        }
    }

    MeshExportBatchErrors::default()
}

fn fatal_mesh_export_error(error: &anyhow::Error) -> MeshExportBatchErrors {
    MeshExportBatchErrors {
        error: Some(format!("{error:#}")),
        material_error: None,
    }
}

fn classify_material_export_error(
    error: &anyhow::Error,
    sidecar: &Path,
    pbr: bool,
) -> MeshExportBatchErrors {
    let mut message = format!("{error:#}");
    match fs::remove_file(sidecar) {
        Ok(()) => {}
        Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {}
        Err(cleanup_error) => {
            message = format!(
                "{message}; failed to remove incomplete material sidecar {}: {cleanup_error}",
                sidecar.display()
            );
        }
    }
    if pbr {
        MeshExportBatchErrors {
            error: Some(message),
            material_error: None,
        }
    } else {
        MeshExportBatchErrors {
            error: None,
            material_error: Some(message),
        }
    }
}

fn should_report_batch_progress(position: usize, job_count: usize) -> bool {
    position == 1 || position == job_count || position.is_multiple_of(100)
}

fn mesh_export_batch_outcome_counts(outcomes: &[MeshExportBatchOutcome]) -> (usize, usize) {
    outcomes.iter().fold((0, 0), |(fatal, material), outcome| {
        (
            fatal + usize::from(outcome.error.is_some()),
            material + usize::from(outcome.material_error.is_some()),
        )
    })
}

fn validate_mesh_export_batch_outputs(jobs: &[MeshExportBatchJob]) -> Result<()> {
    let mut claims = HashMap::<String, (usize, &'static str, PathBuf)>::new();
    for (job_index, job) in jobs.iter().enumerate() {
        let outputs = [
            ("GLB", job.output.clone()),
            (
                "material sidecar",
                job.output.with_extension("Material.json"),
            ),
        ];
        for (kind, path) in outputs {
            let key = mesh_export_output_collision_key(&path)?;
            if let Some((prior_index, prior_kind, prior_path)) = claims.get(&key) {
                anyhow::bail!(
                    "mesh export jobs {} and {} have colliding outputs: {} {} and {} {}",
                    prior_index + 1,
                    job_index + 1,
                    prior_kind,
                    prior_path.display(),
                    kind,
                    path.display()
                );
            }
            claims.insert(key, (job_index, kind, path));
        }
    }
    Ok(())
}

fn mesh_export_output_collision_key(path: &Path) -> Result<String> {
    let absolute = std::path::absolute(path)
        .with_context(|| format!("failed to resolve mesh output path {}", path.display()))?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    let key = normalized.to_string_lossy().into_owned();
    if cfg!(windows) {
        Ok(key.to_lowercase())
    } else {
        Ok(key)
    }
}

fn serialize_archive_resource(
    job: &Cr2wSerializeBatchJob,
    schema: &schema::RedSchema,
    archives: &material::ArchiveSet,
    kraken_path: &std::ffi::OsStr,
) -> Result<()> {
    let bytes = archives
        .read_resource(&job.resource, kraken_path)
        .with_context(|| format!("failed to read archive resource {}", job.resource))?;
    let mut input = NamedTempFile::new()
        .with_context(|| format!("failed to create temporary input for {}", job.resource))?;
    input
        .write_all(&bytes)
        .with_context(|| format!("failed to stage archive resource {}", job.resource))?;
    input
        .flush()
        .with_context(|| format!("failed to flush archive resource {}", job.resource))?;
    let document = codec::decode_wkit_with_red_schema(input.path(), schema, kraken_path)
        .with_context(|| format!("failed to serialize archive resource {}", job.resource))?;
    write_json_atomic(&job.output, &document)
        .with_context(|| format!("failed to write {}", job.output.display()))
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary file beside {}", path.display()))?;
    serde_json::to_writer_pretty(&mut temporary, value)
        .with_context(|| format!("failed to encode JSON for {}", path.display()))?;
    temporary
        .write_all(b"\n")
        .with_context(|| format!("failed to finish JSON for {}", path.display()))?;
    temporary
        .as_file_mut()
        .sync_all()
        .with_context(|| format!("failed to flush JSON for {}", path.display()))?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to replace {} atomically", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_manifest_accepts_job_without_appearance() {
        let manifest: MeshExportBatchManifest = serde_json::from_str(
            r#"{"jobs":[{"mesh":"base\\world\\tile.mesh","output":"tile.glb"}]}"#,
        )
        .expect("fixture manifest should parse");

        assert!(manifest.jobs[0].appearance.is_none());
    }

    #[test]
    fn batch_manifest_should_reject_unknown_top_level_field() {
        let error = serde_json::from_str::<MeshExportBatchManifest>(
            r#"{"jobs":[],"continue_on_error":true}"#,
        )
        .expect_err("unknown manifest fields should be rejected");

        assert!(
            error
                .to_string()
                .contains("unknown field `continue_on_error`")
        );
    }

    #[test]
    fn batch_manifest_should_reject_unknown_job_field() {
        let error = serde_json::from_str::<MeshExportBatchManifest>(
            r#"{"jobs":[{"mesh":"tile.mesh","output":"tile.glb","lod":0}]}"#,
        )
        .expect_err("unknown job fields should be rejected");

        assert!(error.to_string().contains("unknown field `lod`"));
    }

    #[test]
    fn batch_outputs_should_reject_lexically_equivalent_glb_paths() {
        let jobs = vec![
            mesh_export_test_job("first.mesh", "catalog/tile.glb"),
            mesh_export_test_job("second.mesh", "catalog/nested/../tile.glb"),
        ];

        let error = validate_mesh_export_batch_outputs(&jobs)
            .expect_err("equivalent output paths should be rejected");

        assert!(
            error
                .to_string()
                .contains("jobs 1 and 2 have colliding outputs")
        );
    }

    #[test]
    fn batch_outputs_should_reject_shared_material_sidecar_paths() {
        let jobs = vec![
            mesh_export_test_job("first.mesh", "catalog/tile.glb"),
            mesh_export_test_job("second.mesh", "catalog/tile.gltf"),
        ];

        let error = validate_mesh_export_batch_outputs(&jobs)
            .expect_err("shared sidecar paths should be rejected");

        assert!(error.to_string().contains("material sidecar"));
    }

    #[cfg(windows)]
    #[test]
    fn batch_outputs_should_use_case_insensitive_windows_path_semantics() {
        let jobs = vec![
            mesh_export_test_job("first.mesh", "catalog/TILE.glb"),
            mesh_export_test_job("second.mesh", "CATALOG/tile.glb"),
        ];

        let error = validate_mesh_export_batch_outputs(&jobs)
            .expect_err("case-only output differences should be rejected on Windows");

        assert!(error.to_string().contains("colliding outputs"));
    }

    fn mesh_export_test_job(mesh: &str, output: &str) -> MeshExportBatchJob {
        MeshExportBatchJob {
            mesh: mesh.to_owned(),
            appearance: None,
            output: PathBuf::from(output),
        }
    }

    #[test]
    fn non_pbr_material_failure_should_be_a_warning_and_remove_the_sidecar() {
        let workspace = tempfile::tempdir().expect("temporary directory should be available");
        let sidecar = workspace.path().join("tile.Material.json");
        fs::write(&sidecar, b"incomplete").expect("fixture sidecar should be written");

        let material_error = anyhow::anyhow!("malformed material data");
        let errors = classify_material_export_error(&material_error, &sidecar, false);

        assert_eq!(
            (errors, sidecar.exists()),
            (
                MeshExportBatchErrors {
                    error: None,
                    material_error: Some("malformed material data".to_owned()),
                },
                false,
            )
        );
    }

    #[test]
    fn pbr_material_failure_should_remain_fatal() {
        let workspace = tempfile::tempdir().expect("temporary directory should be available");
        let sidecar = workspace.path().join("tile.Material.json");

        let material_error = anyhow::anyhow!("missing texture dependency");
        let errors = classify_material_export_error(&material_error, &sidecar, true);

        assert_eq!(
            errors,
            MeshExportBatchErrors {
                error: Some("missing texture dependency".to_owned()),
                material_error: None,
            }
        );
    }

    #[test]
    fn batch_outcome_counts_should_separate_fatal_failures_and_material_warnings() {
        let outcomes = vec![
            MeshExportBatchOutcome {
                mesh: "complete.mesh".to_owned(),
                appearance: None,
                output: PathBuf::from("complete.glb"),
                error: None,
                material_error: None,
            },
            MeshExportBatchOutcome {
                mesh: "warning.mesh".to_owned(),
                appearance: None,
                output: PathBuf::from("warning.glb"),
                error: None,
                material_error: Some("malformed material".to_owned()),
            },
            MeshExportBatchOutcome {
                mesh: "failed.mesh".to_owned(),
                appearance: None,
                output: PathBuf::from("failed.glb"),
                error: Some("archive read failed".to_owned()),
                material_error: None,
            },
        ];

        assert_eq!(mesh_export_batch_outcome_counts(&outcomes), (1, 1));
    }

    #[test]
    fn batch_progress_should_report_first_last_and_each_hundredth_job() {
        let positions = (1..=250)
            .filter(|position| should_report_batch_progress(*position, 250))
            .collect::<Vec<_>>();

        assert_eq!(positions, vec![1, 100, 200, 250]);
    }

    #[test]
    fn cr2w_serialize_batch_manifest_should_parse_resource_and_output_jobs() {
        let manifest: Cr2wSerializeBatchManifest = serde_json::from_str(
            r#"{"jobs":[{"resource":"base\\worlds\\tile.streamingsector","output":"cache/tile.streamingsector.json"}]}"#,
        )
        .expect("fixture manifest should parse");

        assert_eq!(
            manifest.jobs,
            vec![Cr2wSerializeBatchJob {
                resource: r"base\worlds\tile.streamingsector".to_owned(),
                output: PathBuf::from("cache/tile.streamingsector.json"),
            }]
        );
    }

    #[test]
    fn atomic_json_writer_should_create_parents_and_replace_existing_output() {
        let workspace = tempfile::tempdir().expect("temporary directory should be available");
        let output = workspace.path().join("nested").join("record.json");
        fs::create_dir_all(output.parent().expect("output should have a parent"))
            .expect("fixture parent should be created");
        fs::write(&output, b"stale").expect("fixture output should be written");

        write_json_atomic(&output, &serde_json::json!({"fresh": true}))
            .expect("atomic JSON write should succeed");

        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(output).expect("output should be readable")
            )
            .expect("output should contain valid JSON"),
            serde_json::json!({"fresh": true})
        );
    }
}

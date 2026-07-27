//! Differential CR2W corpus audit against a `WolvenKit` console installation.

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use ghostline_red::{archive, codec, kraken, schema, writer};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Mutex,
};

const DEFAULT_SHARD_SIZE: usize = 5_000;
const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;
const WOLVENKIT_WORKERS: usize = 1;
const MIN_PARALLEL_WOLVENKIT_FILES: usize = 200;

#[derive(Debug, Parser)]
#[command(about = "Audit vanilla CR2W serialization and deserialization against WolvenKit")]
struct Args {
    /// Directory containing vanilla `.archive` files.
    archives: PathBuf,
    /// `WolvenKit` console executable.
    #[arg(long)]
    wolvenkit: PathBuf,
    /// Schema sources in increasing precedence order.
    #[arg(long, required = true)]
    schema: Vec<PathBuf>,
    /// Persistent report and temporary-work root.
    #[arg(long)]
    output: PathBuf,
    /// Process only archives with one of these exact file names.
    #[arg(long)]
    archive: Vec<String>,
    /// Process only entries with these hexadecimal or decimal depot-path hashes.
    #[arg(long, value_parser = parse_hash)]
    hash: Vec<u64>,
    /// Number of archive entries processed in one resumable shard.
    #[arg(long, default_value_t = DEFAULT_SHARD_SIZE)]
    shard_size: usize,
    /// Re-run shards that already have a report.
    #[arg(long)]
    force: bool,
    /// Stop after this many shards (useful for a smoke test).
    #[arg(long)]
    max_shards: Option<usize>,
    /// Preserve per-shard staged binaries and `WolvenKit` JSON for diagnosis.
    #[arg(long)]
    keep_work: bool,
    /// Stop after native extraction and CR2W detection without invoking either serializer.
    #[arg(long)]
    stage_only: bool,
}

#[derive(Debug, Default, Serialize)]
struct Summary {
    archive_entries: usize,
    cr2w_files: usize,
    extraction_failures: usize,
    wolvenkit_serialized: usize,
    ghostline_serialized: usize,
    serialize_data_equal: usize,
    ghostline_from_wolvenkit: usize,
    ghostline_from_wolvenkit_exact_original: usize,
    wolvenkit_reserialized_ghostline: usize,
    deserialize_data_equal: usize,
}

#[derive(Debug, Default, Serialize)]
struct TypeSummary {
    files: usize,
    ghostline_serialized: usize,
    serialize_data_equal: usize,
    ghostline_from_wolvenkit_exact_original: usize,
    deserialize_data_equal: usize,
}

#[derive(Debug, Serialize)]
struct Failure {
    name_hash: String,
    phase: &'static str,
    root_type: Option<String>,
    detail: String,
}

#[derive(Debug, Serialize)]
struct ToolRun {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize)]
struct ShardReport {
    archive: String,
    entry_start: usize,
    entry_end: usize,
    summary: Summary,
    types: BTreeMap<String, TypeSummary>,
    wolvenkit_serialize: ToolRun,
    wolvenkit_serialize_ghostline_rebuilt: ToolRun,
    failures: Vec<Failure>,
}

#[derive(Debug)]
struct StagedFile {
    name_hash: u64,
    path: PathBuf,
}

#[derive(Debug)]
struct Difference {
    path: String,
    expected: String,
    actual: String,
}

#[derive(Debug)]
struct AuditState {
    summary: Summary,
    types: BTreeMap<String, TypeSummary>,
    failures: Vec<Failure>,
}

#[derive(Clone, Copy)]
struct AuditSchema<'a> {
    schema: &'a schema::RedSchema,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.shard_size == 0 {
        bail!("--shard-size must be greater than zero");
    }
    validate_inputs(&args)?;

    let mut red_schema = schema::RedSchema::default();
    for path in &args.schema {
        red_schema.merge(
            schema::RedSchema::from_slice(&fs::read(path)?)
                .with_context(|| format!("failed to read schema {}", path.display()))?,
        );
    }
    let reports = args.output.join("reports");
    let temporary = args.output.join("work");
    fs::create_dir_all(&reports)?;
    fs::create_dir_all(&temporary)?;

    let mut archives = collect_archives(&args)?;
    archives.sort();
    let mut completed_shards = 0_usize;
    for archive_path in archives {
        let index = archive::read_archive(&archive_path)
            .with_context(|| format!("failed to index {}", archive_path.display()))?;
        let archive_name = file_name(&archive_path)?;
        let ranges = entry_ranges(&index, &args.hash, args.shard_size);
        for (entry_start, entry_end) in ranges {
            if args
                .max_shards
                .is_some_and(|maximum| completed_shards >= maximum)
            {
                return Ok(());
            }
            let report_path = reports.join(format!(
                "{archive_name}.{entry_start:09}-{entry_end:09}.json"
            ));
            if report_path.exists() && !args.force {
                println!("SKIP {archive_name} {entry_start}..{entry_end}");
                continue;
            }
            println!("START {archive_name} {entry_start}..{entry_end}");
            let workspace = tempfile::Builder::new()
                .prefix(&format!("{archive_name}-{entry_start:09}-"))
                .tempdir_in(&temporary)?;
            let report = audit_shard(
                &archive_path,
                &index,
                entry_start,
                entry_end,
                &args.wolvenkit,
                AuditSchema {
                    schema: &red_schema,
                },
                workspace.path(),
                args.stage_only,
            )?;
            write_json(&report_path, &report)?;
            if args.keep_work {
                println!("KEEP  {}", workspace.keep().display());
            }
            println!(
                "DONE  {} {}..{}: {} CR2W, {} serialize matches, {} failures",
                archive_name,
                entry_start,
                entry_end,
                report.summary.cr2w_files,
                report.summary.serialize_data_equal,
                report.failures.len()
            );
            completed_shards += 1;
        }
    }
    Ok(())
}

fn parse_hash(value: &str) -> Result<u64, String> {
    let value = value.trim();
    let hexadecimal = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    match hexadecimal {
        Some(value) => u64::from_str_radix(value, 16),
        None if value.bytes().any(|byte| byte.is_ascii_alphabetic()) => {
            u64::from_str_radix(value, 16)
        }
        None => value.parse(),
    }
    .map_err(|error| format!("invalid depot-path hash {value:?}: {error}"))
}

fn entry_ranges(
    index: &archive::ArchiveIndex,
    hashes: &[u64],
    shard_size: usize,
) -> Vec<(usize, usize)> {
    if hashes.is_empty() {
        return (0..index.entries.len())
            .step_by(shard_size)
            .map(|start| {
                (
                    start,
                    start.saturating_add(shard_size).min(index.entries.len()),
                )
            })
            .collect();
    }
    let hashes = hashes.iter().copied().collect::<BTreeSet<_>>();
    index
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| hashes.contains(&entry.name_hash))
        .map(|(index, _)| (index, index + 1))
        .collect()
}

fn validate_inputs(args: &Args) -> Result<()> {
    if !args.archives.is_dir() {
        bail!(
            "archive directory does not exist: {}",
            args.archives.display()
        );
    }
    if !args.wolvenkit.is_file() {
        bail!(
            "WolvenKit executable does not exist: {}",
            args.wolvenkit.display()
        );
    }
    for schema in &args.schema {
        if !schema.is_file() {
            bail!("schema does not exist: {}", schema.display());
        }
    }
    Ok(())
}

fn collect_archives(args: &Args) -> Result<Vec<PathBuf>> {
    let requested: BTreeSet<&str> = args.archive.iter().map(String::as_str).collect();
    let archives = fs::read_dir(&args.archives)?
        .filter_map(|item| item.ok().map(|item| item.path()))
        .filter(|path| {
            path.extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| extension.eq_ignore_ascii_case("archive"))
        })
        .filter(|path| {
            requested.is_empty()
                || path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| requested.contains(name))
        })
        .collect::<Vec<_>>();
    if archives.is_empty() {
        bail!("no matching .archive files found");
    }
    Ok(archives)
}

#[expect(
    clippy::too_many_lines,
    reason = "the audit keeps each oracle comparison explicit and locally reviewable"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the shard boundary keeps reusable corpus state explicit"
)]
fn audit_shard(
    archive_path: &Path,
    index: &archive::ArchiveIndex,
    entry_start: usize,
    entry_end: usize,
    wolvenkit: &Path,
    schema: AuditSchema<'_>,
    workspace: &Path,
    stage_only: bool,
) -> Result<ShardReport> {
    let staged_root = workspace.join("staged");
    let wkit_json_root = workspace.join("wkit-json");
    let red_from_wkit_root = workspace.join("red-from-wkit");
    let wkit_rebuilt_json_root = workspace.join("wkit-rebuilt-json");
    for directory in [
        &staged_root,
        &wkit_json_root,
        &red_from_wkit_root,
        &wkit_rebuilt_json_root,
    ] {
        fs::create_dir_all(directory)?;
    }

    let mut summary = Summary {
        archive_entries: entry_end - entry_start,
        ..Summary::default()
    };
    let mut failures = Vec::new();
    let staged = stage_cr2w_files(
        archive_path,
        index,
        entry_start,
        entry_end,
        &staged_root,
        &mut failures,
    )?;
    summary.cr2w_files = staged.len();
    summary.extraction_failures = failures.len();

    if stage_only {
        let skipped = || ToolRun {
            exit_code: Some(0),
            stdout: "skipped: --stage-only".to_owned(),
            stderr: String::new(),
        };
        return Ok(ShardReport {
            archive: file_name(archive_path)?,
            entry_start,
            entry_end,
            summary,
            types: BTreeMap::new(),
            wolvenkit_serialize: skipped(),
            wolvenkit_serialize_ghostline_rebuilt: skipped(),
            failures,
        });
    }

    let wolvenkit_serialize = run_wolvenkit(wolvenkit, "serialize", &staged_root, &wkit_json_root)?;
    let missing_kraken = workspace.join("missing-kraken.dll");
    let state = Mutex::new(AuditState {
        summary,
        types: BTreeMap::new(),
        failures,
    });

    staged.par_iter().try_for_each(|file| -> Result<()> {
        let mut summary = Summary::default();
        let mut types = BTreeMap::<String, TypeSummary>::new();
        let mut failures = Vec::new();
        let hash = hash_text(file.name_hash);
        let json_name = format!("{hash}.scene.json");
        let binary_name = format!("{hash}.scene");
        let wkit_json_path = wkit_json_root.join(&json_name);
        let original = &file.path;

        let wkit_document = match read_optional_json(&wkit_json_path) {
            Ok(document) => document,
            Err(error) => {
                failures.push(Failure {
                    name_hash: hash.clone(),
                    phase: "wolvenkit_serialize_invalid_json",
                    root_type: None,
                    detail: error.to_string(),
                });
                None
            }
        };
        let root_type = wkit_document.as_ref().and_then(root_type);
        let type_key = root_type.clone().unwrap_or_else(|| "<unknown>".to_owned());
        types.entry(type_key.clone()).or_default().files += 1;
        if wkit_document.is_some() {
            summary.wolvenkit_serialized += 1;
        } else if !wkit_json_path.is_file() {
            failures.push(Failure {
                name_hash: hash.clone(),
                phase: "wolvenkit_serialize",
                root_type: root_type.clone(),
                detail: "WolvenKit produced no JSON output".to_owned(),
            });
        }

        let red_document = match codec::decode_wkit_with_red_schema(
            original,
            schema.schema,
            missing_kraken.as_os_str(),
        ) {
            Ok(document) => {
                summary.ghostline_serialized += 1;
                types
                    .entry(type_key.clone())
                    .or_default()
                    .ghostline_serialized += 1;
                Some(document)
            }
            Err(error) => {
                failures.push(Failure {
                    name_hash: hash.clone(),
                    phase: "ghostline_serialize",
                    root_type: root_type.clone(),
                    detail: error.to_string(),
                });
                None
            }
        };

        if let (Some(expected), Some(actual)) = (&wkit_document, &red_document) {
            match first_difference(
                expected.get("Data"),
                actual.get("Data"),
                "$.Data".to_owned(),
            ) {
                None => {
                    summary.serialize_data_equal += 1;
                    types
                        .entry(type_key.clone())
                        .or_default()
                        .serialize_data_equal += 1;
                }
                Some(difference) => failures.push(Failure {
                    name_hash: hash.clone(),
                    phase: "serialize_data_diff",
                    root_type: root_type.clone(),
                    detail: format!(
                        "{}: expected {}, actual {}",
                        difference.path, difference.expected, difference.actual
                    ),
                }),
            }
        }

        if wkit_document.is_some() {
            let output = red_from_wkit_root.join(&binary_name);
            match writer::write_with_red_schema(
                &wkit_json_path,
                original,
                &output,
                schema.schema,
                missing_kraken.as_os_str(),
            ) {
                Ok(()) => {
                    summary.ghostline_from_wolvenkit += 1;
                    if files_equal(original, &output)? {
                        summary.ghostline_from_wolvenkit_exact_original += 1;
                        summary.deserialize_data_equal += 1;
                        types
                            .entry(type_key.clone())
                            .or_default()
                            .ghostline_from_wolvenkit_exact_original += 1;
                        types
                            .entry(type_key.clone())
                            .or_default()
                            .deserialize_data_equal += 1;
                        fs::remove_file(&output)?;
                    } else {
                        failures.push(Failure {
                            name_hash: hash.clone(),
                            phase: "ghostline_deserialize_wolvenkit_binary_diff",
                            root_type: root_type.clone(),
                            detail: "rebuilt binary differs from the vanilla template".to_owned(),
                        });
                    }
                }
                Err(error) => failures.push(Failure {
                    name_hash: hash.clone(),
                    phase: "ghostline_deserialize_wolvenkit",
                    root_type: root_type.clone(),
                    detail: error.to_string(),
                }),
            }
        }

        if let Some(document) = wkit_document {
            drop_json(document);
        }
        if let Some(document) = red_document {
            drop_json(document);
        }
        let mut state = state
            .lock()
            .map_err(|_| anyhow!("audit aggregation lock was poisoned"))?;
        merge_summary(&mut state.summary, &summary);
        merge_types(&mut state.types, types);
        state.failures.append(&mut failures);
        Ok(())
    })?;
    let AuditState {
        mut summary,
        mut types,
        mut failures,
    } = state
        .into_inner()
        .map_err(|_| anyhow!("audit aggregation lock was poisoned"))?;

    let wolvenkit_serialize_ghostline_rebuilt = run_wolvenkit(
        wolvenkit,
        "serialize",
        &red_from_wkit_root,
        &wkit_rebuilt_json_root,
    )?;

    let rebuilt_files = fs::read_dir(&red_from_wkit_root)?
        .filter_map(|item| item.ok().map(|item| item.path()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    for file in rebuilt_files {
        let hash = file
            .file_stem()
            .and_then(OsStr::to_str)
            .ok_or_else(|| anyhow!("rebuilt CR2W has no UTF-8 file stem"))?
            .to_owned();
        let json_name = format!("{hash}.scene.json");
        let reference = read_optional_json(&wkit_json_root.join(&json_name))
            .ok()
            .flatten();
        let root_type = reference.as_ref().and_then(root_type);
        let type_key = root_type.clone().unwrap_or_else(|| "<unknown>".to_owned());
        let rebuilt_path = wkit_rebuilt_json_root.join(&json_name);
        let rebuilt = match read_optional_json(&rebuilt_path) {
            Ok(document) => document,
            Err(error) => {
                failures.push(Failure {
                    name_hash: hash.clone(),
                    phase: "wolvenkit_serialize_ghostline_rebuilt_invalid_json",
                    root_type: root_type.clone(),
                    detail: error.to_string(),
                });
                None
            }
        };
        if rebuilt.is_some() {
            summary.wolvenkit_reserialized_ghostline += 1;
        } else if red_from_wkit_root.join(format!("{hash}.scene")).is_file()
            && !rebuilt_path.is_file()
        {
            failures.push(Failure {
                name_hash: hash.clone(),
                phase: "wolvenkit_serialize_ghostline_rebuilt",
                root_type: root_type.clone(),
                detail: "WolvenKit produced no JSON for ghostline's rebuilt binary".to_owned(),
            });
        }
        if let (Some(expected), Some(actual)) = (&reference, &rebuilt) {
            match first_difference(
                expected.get("Data"),
                actual.get("Data"),
                "$.Data".to_owned(),
            ) {
                None => {
                    summary.deserialize_data_equal += 1;
                    types.entry(type_key).or_default().deserialize_data_equal += 1;
                }
                Some(difference) => failures.push(Failure {
                    name_hash: hash,
                    phase: "deserialize_data_diff",
                    root_type,
                    detail: format!(
                        "{}: expected {}, actual {}",
                        difference.path, difference.expected, difference.actual
                    ),
                }),
            }
        }
        if let Some(document) = reference {
            drop_json(document);
        }
        if let Some(document) = rebuilt {
            drop_json(document);
        }
    }

    Ok(ShardReport {
        archive: file_name(archive_path)?,
        entry_start,
        entry_end,
        summary,
        types,
        wolvenkit_serialize,
        wolvenkit_serialize_ghostline_rebuilt,
        failures,
    })
}

fn merge_summary(target: &mut Summary, source: &Summary) {
    target.wolvenkit_serialized += source.wolvenkit_serialized;
    target.ghostline_serialized += source.ghostline_serialized;
    target.serialize_data_equal += source.serialize_data_equal;
    target.ghostline_from_wolvenkit += source.ghostline_from_wolvenkit;
    target.ghostline_from_wolvenkit_exact_original +=
        source.ghostline_from_wolvenkit_exact_original;
    target.wolvenkit_reserialized_ghostline += source.wolvenkit_reserialized_ghostline;
    target.deserialize_data_equal += source.deserialize_data_equal;
}

fn merge_types(target: &mut BTreeMap<String, TypeSummary>, source: BTreeMap<String, TypeSummary>) {
    for (name, source) in source {
        let target = target.entry(name).or_default();
        target.files += source.files;
        target.ghostline_serialized += source.ghostline_serialized;
        target.serialize_data_equal += source.serialize_data_equal;
        target.ghostline_from_wolvenkit_exact_original +=
            source.ghostline_from_wolvenkit_exact_original;
        target.deserialize_data_equal += source.deserialize_data_equal;
    }
}

fn stage_cr2w_files(
    archive_path: &Path,
    index: &archive::ArchiveIndex,
    entry_start: usize,
    entry_end: usize,
    output: &Path,
    failures: &mut Vec<Failure>,
) -> Result<Vec<StagedFile>> {
    let mut reader = BufReader::new(File::open(archive_path)?);
    let mut staged = Vec::new();
    for (relative_index, entry) in index.entries[entry_start..entry_end].iter().enumerate() {
        let entry_index = entry_start + relative_index;
        match stage_entry(&mut reader, index, entry_index, output) {
            Ok(Some(file)) => staged.push(file),
            Ok(None) => {}
            Err(error) => failures.push(Failure {
                name_hash: hash_text(entry.name_hash),
                phase: "extract_cr2w",
                root_type: None,
                detail: error.to_string(),
            }),
        }
    }
    Ok(staged)
}

fn stage_entry(
    reader: &mut (impl Read + Seek),
    index: &archive::ArchiveIndex,
    entry_index: usize,
    output: &Path,
) -> Result<Option<StagedFile>> {
    let entry = index
        .entries
        .get(entry_index)
        .ok_or_else(|| anyhow!("entry index {entry_index} is out of range"))?;
    let start = usize::try_from(entry.segments_start)?;
    let end = usize::try_from(entry.segments_end)?;
    let segments = index
        .segments
        .get(start..end)
        .ok_or_else(|| anyhow!("invalid segment range {start}..{end}"))?;
    let Some((&main_segment, buffer_segments)) = segments.split_first() else {
        return Ok(None);
    };
    let failed_kraken = output.join(format!("{}.kraken", hash_text(entry.name_hash)));
    let Some(main) = read_main_if_cr2w(reader, main_segment, &failed_kraken)? else {
        return Ok(None);
    };

    let name_hash = entry.name_hash;
    let path = output.join(format!("{}.scene", hash_text(name_hash)));
    let mut target = BufWriter::new(File::create(&path)?);
    target.write_all(&main)?;
    for segment in buffer_segments {
        copy_segment(reader, &mut target, *segment)?;
    }
    target.flush()?;
    Ok(Some(StagedFile { name_hash, path }))
}

fn read_main_if_cr2w(
    reader: &mut (impl Read + Seek),
    segment: archive::ArchiveSegment,
    failed_kraken: &Path,
) -> Result<Option<Vec<u8>>> {
    let compressed_size = usize::try_from(segment.compressed_size)?;
    if compressed_size < 4 {
        return Ok(None);
    }
    reader.seek(SeekFrom::Start(segment.offset))?;
    let mut prefix = [0_u8; 8];
    let prefix_len = compressed_size.min(prefix.len());
    reader.read_exact(&mut prefix[..prefix_len])?;

    if prefix.get(..4) == Some(b"CR2W") {
        let mut bytes = vec![0_u8; compressed_size];
        bytes[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
        reader.read_exact(&mut bytes[prefix_len..])?;
        return Ok(Some(bytes));
    }
    if prefix.get(..4) != Some(b"KARK") || prefix_len < 8 {
        return Ok(None);
    }

    let declared = u32::from_le_bytes(prefix[4..8].try_into()?);
    let mut payload = vec![0_u8; compressed_size];
    payload[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
    reader.read_exact(&mut payload[prefix_len..])?;
    let decoded = kraken::decode(&payload[8..], usize::try_from(declared)?).map_err(|error| {
        let _ = fs::write(failed_kraken, &payload);
        anyhow!("native Kraken decode failed: {error}")
    })?;
    Ok(decoded.starts_with(b"CR2W").then_some(decoded))
}

fn copy_segment(
    reader: &mut (impl Read + Seek),
    writer: &mut impl Write,
    segment: archive::ArchiveSegment,
) -> Result<()> {
    reader.seek(SeekFrom::Start(segment.offset))?;
    let mut remaining = u64::from(segment.compressed_size);
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))?;
        reader.read_exact(&mut buffer[..count])?;
        writer.write_all(&buffer[..count])?;
        remaining -= u64::try_from(count)?;
    }
    Ok(())
}

fn run_wolvenkit(
    executable: &Path,
    operation: &str,
    input: &Path,
    output: &Path,
) -> Result<ToolRun> {
    let files = fs::read_dir(input)?
        .filter_map(|item| item.ok().map(|item| item.path()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    if files.is_empty() {
        return Ok(ToolRun {
            exit_code: Some(0),
            stdout: "skipped: input directory is empty".to_owned(),
            stderr: String::new(),
        });
    }
    if files.len() < MIN_PARALLEL_WOLVENKIT_FILES {
        return run_wolvenkit_one(executable, operation, input, output);
    }

    let worker_count = WOLVENKIT_WORKERS.min(files.len());
    if worker_count == 1 {
        return run_wolvenkit_one(executable, operation, input, output);
    }
    let input_name = input
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("WolvenKit input has no UTF-8 file name"))?;
    let workers_root = input
        .parent()
        .ok_or_else(|| anyhow!("WolvenKit input has no parent directory"))?
        .join(format!("{input_name}-{operation}-workers"));
    let worker_inputs = (0..worker_count)
        .map(|index| workers_root.join(index.to_string()))
        .collect::<Vec<_>>();
    for directory in &worker_inputs {
        fs::create_dir_all(directory)?;
    }
    for (index, path) in files.iter().enumerate() {
        let target = worker_inputs[index % worker_count].join(
            path.file_name()
                .ok_or_else(|| anyhow!("WolvenKit input file has no name"))?,
        );
        fs::hard_link(path, &target).or_else(|_| fs::copy(path, target).map(|_| ()))?;
    }
    let runs = worker_inputs
        .par_iter()
        .map(|worker| run_wolvenkit_one(executable, operation, worker, output))
        .collect::<Result<Vec<_>>>()?;
    let exit_code = runs
        .iter()
        .find_map(|run| (run.exit_code != Some(0)).then_some(run.exit_code))
        .unwrap_or(Some(0));
    let stdout = runs
        .iter()
        .map(|run| run.stdout.as_str())
        .collect::<String>();
    let stderr = runs
        .iter()
        .map(|run| run.stderr.as_str())
        .collect::<String>();
    Ok(ToolRun {
        exit_code,
        stdout: tail_text(stdout.as_bytes()),
        stderr: tail_text(stderr.as_bytes()),
    })
}

fn run_wolvenkit_one(
    executable: &Path,
    operation: &str,
    input: &Path,
    output: &Path,
) -> Result<ToolRun> {
    let process = Command::new(executable)
        .current_dir(
            executable
                .parent()
                .ok_or_else(|| anyhow!("WolvenKit executable has no parent directory"))?,
        )
        .args(["convert", operation])
        .arg(input)
        .args(["--outpath"])
        .arg(output)
        .args(["--verbosity", "minimal"])
        .output()
        .with_context(|| format!("failed to start {}", executable.display()))?;
    Ok(tool_run(&process))
}

fn tool_run(output: &Output) -> ToolRun {
    ToolRun {
        exit_code: output.status.code(),
        stdout: tail_text(&output.stdout),
        stderr: tail_text(&output.stderr),
    }
}

fn tail_text(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(MAX_DIAGNOSTIC_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

fn read_optional_json(path: &Path) -> Result<Option<Value>> {
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
    Value::deserialize(deserializer)
        .map(Some)
        .with_context(|| format!("failed to parse {}", path.display()))
}

fn root_type(document: &Value) -> Option<String> {
    document
        .pointer("/Data/RootChunk/$type")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn first_difference(
    expected: Option<&Value>,
    actual: Option<&Value>,
    path: String,
) -> Option<Difference> {
    enum Work<'a> {
        Compare(Option<&'a Value>, Option<&'a Value>, String),
        Difference(Difference),
    }

    let mut pending = vec![Work::Compare(expected, actual, path)];
    while let Some(work) = pending.pop() {
        let Work::Compare(expected, actual, path) = work else {
            let Work::Difference(difference) = work else {
                unreachable!("work item is one of the two declared variants");
            };
            return Some(difference);
        };
        match (expected, actual) {
            (Some(Value::Object(expected)), Some(Value::Object(actual))) => {
                if let Some(key) = actual.keys().find(|key| !expected.contains_key(*key)) {
                    pending.push(Work::Difference(Difference {
                        path: format!("{path}.{key}"),
                        expected: "<missing>".to_owned(),
                        actual: compact_value(actual.get(key)),
                    }));
                }
                for (key, expected_value) in expected.iter().rev() {
                    pending.push(Work::Compare(
                        Some(expected_value),
                        actual.get(key),
                        format!("{path}.{key}"),
                    ));
                }
            }
            (Some(Value::Array(expected)), Some(Value::Array(actual))) => {
                if expected.len() != actual.len() {
                    pending.push(Work::Difference(Difference {
                        path: path.clone(),
                        expected: format!("array length {}", expected.len()),
                        actual: format!("array length {}", actual.len()),
                    }));
                }
                for (index, expected_value) in expected.iter().enumerate().rev() {
                    pending.push(Work::Compare(
                        Some(expected_value),
                        actual.get(index),
                        format!("{path}[{index}]"),
                    ));
                }
            }
            (Some(expected), Some(actual)) if expected == actual => {}
            (expected, actual) => {
                return Some(Difference {
                    path,
                    expected: compact_value(expected),
                    actual: compact_value(actual),
                });
            }
        }
    }
    None
}

fn compact_value(value: Option<&Value>) -> String {
    match value {
        None => "<missing>".to_owned(),
        Some(Value::Null) => "null".to_owned(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::String(value)) => format!("{value:?}"),
        Some(Value::Array(value)) => format!("array length {}", value.len()),
        Some(Value::Object(value)) => format!("object with {} keys", value.len()),
    }
}

fn drop_json(value: Value) {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => pending.extend(values.into_values()),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
}

fn files_equal(left: &Path, right: &Path) -> Result<bool> {
    if fs::metadata(left)?.len() != fs::metadata(right)?.len() {
        return Ok(false);
    }
    let mut left = BufReader::new(File::open(left)?);
    let mut right = BufReader::new(File::open(right)?);
    let mut left_buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut right_buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let left_count = left.read(&mut left_buffer)?;
        let right_count = right.read(&mut right_buffer)?;
        if left_count != right_count || left_buffer[..left_count] != right_buffer[..right_count] {
            return Ok(false);
        }
        if left_count == 0 {
            return Ok(true);
        }
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut bytes, formatter);
    value.serialize(serde_stacker::Serializer::new(&mut serializer))?;
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

fn hash_text(hash: u64) -> String {
    format!("{hash:016x}")
}

fn file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(OsStr::to_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("path has no UTF-8 file name: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn first_difference_reports_nested_array_member() {
        let expected = json!({"root": [{"value": 1}]});
        let actual = json!({"root": [{"value": 2}]});
        let difference = first_difference(Some(&expected), Some(&actual), "$".to_owned()).unwrap();
        assert_eq!(difference.path, "$.root[0].value");
        assert_eq!(difference.expected, "1");
        assert_eq!(difference.actual, "2");
    }

    #[test]
    fn first_difference_ignores_object_key_order() {
        let expected = json!({"first": 1, "second": 2});
        let actual = json!({"second": 2, "first": 1});
        assert!(first_difference(Some(&expected), Some(&actual), "$".to_owned()).is_none());
    }

    #[test]
    fn parse_hash_accepts_decimal_and_hexadecimal() {
        assert_eq!(parse_hash("42").unwrap(), 42);
        assert_eq!(parse_hash("0x2a").unwrap(), 42);
        assert_eq!(parse_hash("000000000000002a").unwrap(), 42);
    }
}

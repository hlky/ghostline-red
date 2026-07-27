//! Consolidate resumable vanilla CR2W audit shards into compact reports.

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Reverse,
    collections::BTreeMap,
    fmt::Write as _,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
};

const EXAMPLES_PER_PHASE: usize = 5;
const MAX_EXAMPLE_CHARS: usize = 240;

#[derive(Debug, Parser)]
#[command(about = "Summarize vanilla-cr2w-audit shard reports")]
struct Args {
    /// Directory containing audit shard JSON files.
    reports: PathBuf,
    /// Markdown summary to write. A JSON summary is written alongside it.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct Summary {
    archive_entries: u64,
    cr2w_files: u64,
    extraction_failures: u64,
    wolvenkit_serialized: u64,
    ghostline_serialized: u64,
    serialize_data_equal: u64,
    ghostline_from_wolvenkit: u64,
    ghostline_from_wolvenkit_exact_original: u64,
    wolvenkit_reserialized_ghostline: u64,
    deserialize_data_equal: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct TypeSummary {
    files: u64,
    ghostline_serialized: u64,
    serialize_data_equal: u64,
    ghostline_from_wolvenkit_exact_original: u64,
    deserialize_data_equal: u64,
}

#[derive(Debug, Deserialize)]
struct Failure {
    name_hash: String,
    phase: String,
    root_type: Option<String>,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct ShardReport {
    archive: String,
    summary: Summary,
    types: BTreeMap<String, TypeSummary>,
    failures: Vec<Failure>,
}

#[derive(Debug, Serialize)]
struct FailureExample {
    archive: String,
    name_hash: String,
    root_type: Option<String>,
    detail: String,
}

#[derive(Debug, Serialize)]
struct ConsolidatedReport {
    shard_reports: usize,
    totals: Summary,
    archives: BTreeMap<String, Summary>,
    failure_phases: BTreeMap<String, u64>,
    types: BTreeMap<String, TypeSummary>,
    examples: BTreeMap<String, Vec<FailureExample>>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if !args.reports.is_dir() {
        bail!(
            "audit report directory does not exist: {}",
            args.reports.display()
        );
    }

    let report = consolidate(&args.reports)?;
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.output, render_markdown(&report))
        .with_context(|| format!("failed to write {}", args.output.display()))?;
    let json_path = args.output.with_extension("json");
    fs::write(&json_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("failed to write {}", json_path.display()))?;
    println!("{}", args.output.display());
    println!("{}", json_path.display());
    Ok(())
}

fn consolidate(reports: &Path) -> Result<ConsolidatedReport> {
    let mut paths = fs::read_dir(reports)?
        .filter_map(|item| item.ok().map(|item| item.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        })
        .collect::<Vec<_>>();
    paths.sort();
    if paths.is_empty() {
        bail!("no audit shard JSON files found in {}", reports.display());
    }

    let mut totals = Summary::default();
    let mut archives = BTreeMap::<String, Summary>::new();
    let mut failure_phases = BTreeMap::<String, u64>::new();
    let mut types = BTreeMap::<String, TypeSummary>::new();
    let mut examples = BTreeMap::<String, Vec<FailureExample>>::new();

    for path in &paths {
        let shard: ShardReport = serde_json::from_reader(BufReader::new(File::open(path)?))
            .with_context(|| format!("failed to parse {}", path.display()))?;
        merge_summary(&mut totals, &shard.summary);
        merge_summary(
            archives.entry(shard.archive.clone()).or_default(),
            &shard.summary,
        );
        merge_types(&mut types, shard.types);
        for failure in shard.failures {
            *failure_phases.entry(failure.phase.clone()).or_default() += 1;
            let phase_examples = examples.entry(failure.phase).or_default();
            if phase_examples.len() < EXAMPLES_PER_PHASE {
                phase_examples.push(FailureExample {
                    archive: shard.archive.clone(),
                    name_hash: failure.name_hash,
                    root_type: failure.root_type,
                    detail: truncate(&failure.detail, MAX_EXAMPLE_CHARS),
                });
            }
        }
    }

    Ok(ConsolidatedReport {
        shard_reports: paths.len(),
        totals,
        archives,
        failure_phases,
        types,
        examples,
    })
}

fn merge_summary(target: &mut Summary, source: &Summary) {
    target.archive_entries += source.archive_entries;
    target.cr2w_files += source.cr2w_files;
    target.extraction_failures += source.extraction_failures;
    target.wolvenkit_serialized += source.wolvenkit_serialized;
    target.ghostline_serialized += source.ghostline_serialized;
    target.serialize_data_equal += source.serialize_data_equal;
    target.ghostline_from_wolvenkit += source.ghostline_from_wolvenkit;
    target.ghostline_from_wolvenkit_exact_original +=
        source.ghostline_from_wolvenkit_exact_original;
    target.wolvenkit_reserialized_ghostline += source.wolvenkit_reserialized_ghostline;
    target.deserialize_data_equal += source
        .deserialize_data_equal
        .max(source.ghostline_from_wolvenkit_exact_original);
}

fn merge_types(target: &mut BTreeMap<String, TypeSummary>, source: BTreeMap<String, TypeSummary>) {
    for (name, source) in source {
        let target = target.entry(name).or_default();
        target.files += source.files;
        target.ghostline_serialized += source.ghostline_serialized;
        target.serialize_data_equal += source.serialize_data_equal;
        target.ghostline_from_wolvenkit_exact_original +=
            source.ghostline_from_wolvenkit_exact_original;
        target.deserialize_data_equal += source
            .deserialize_data_equal
            .max(source.ghostline_from_wolvenkit_exact_original);
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the generated report layout is clearer when its sections remain together"
)]
fn render_markdown(report: &ConsolidatedReport) -> String {
    let totals = &report.totals;
    let mut output = String::new();
    writeln!(output, "# Vanilla CR2W differential audit\n").unwrap();
    writeln!(output, "- Shard reports: {}", report.shard_reports).unwrap();
    writeln!(
        output,
        "- Archive entries inspected: {}",
        totals.archive_entries
    )
    .unwrap();
    writeln!(output, "- CR2W resources staged: {}", totals.cr2w_files).unwrap();
    writeln!(
        output,
        "- WolvenKit serialization oracle successes: {} ({})",
        totals.wolvenkit_serialized,
        percent(totals.wolvenkit_serialized, totals.cr2w_files)
    )
    .unwrap();
    writeln!(
        output,
        "- ghostline-red serialization successes: {} ({})",
        totals.ghostline_serialized,
        percent(totals.ghostline_serialized, totals.wolvenkit_serialized)
    )
    .unwrap();
    writeln!(
        output,
        "- Exact WolvenKit `Data` matches after serialization: {} ({})",
        totals.serialize_data_equal,
        percent(totals.serialize_data_equal, totals.wolvenkit_serialized)
    )
    .unwrap();
    writeln!(
        output,
        "- ghostline-red deserialization successes: {} ({})",
        totals.ghostline_from_wolvenkit,
        percent(totals.ghostline_from_wolvenkit, totals.wolvenkit_serialized)
    )
    .unwrap();
    writeln!(
        output,
        "- Byte-identical vanilla rebuilds: {} ({})",
        totals.ghostline_from_wolvenkit_exact_original,
        percent(
            totals.ghostline_from_wolvenkit_exact_original,
            totals.wolvenkit_serialized
        )
    )
    .unwrap();
    writeln!(
        output,
        "- Semantically equal rebuilds: {} ({})",
        totals.deserialize_data_equal,
        percent(totals.deserialize_data_equal, totals.wolvenkit_serialized)
    )
    .unwrap();
    writeln!(
        output,
        "- Native Kraken staging failures: {}\n",
        totals.extraction_failures
    )
    .unwrap();

    writeln!(output, "## Divergences by phase\n").unwrap();
    writeln!(output, "| Phase | Count |").unwrap();
    writeln!(output, "|---|---:|").unwrap();
    let mut phases = report.failure_phases.iter().collect::<Vec<_>>();
    phases.sort_by_key(|(_, count)| Reverse(**count));
    for (phase, count) in phases {
        writeln!(output, "| `{phase}` | {count} |").unwrap();
    }

    writeln!(output, "\n## Most common root types\n").unwrap();
    writeln!(
        output,
        "| Root type | Files | Serialized | Serialize matches | Exact rebuilds | Semantic rebuilds |"
    )
    .unwrap();
    writeln!(output, "|---|---:|---:|---:|---:|---:|").unwrap();
    let mut types = report.types.iter().collect::<Vec<_>>();
    types.sort_by_key(|(_, summary)| Reverse(summary.files));
    for (name, summary) in types.into_iter().take(50) {
        writeln!(
            output,
            "| `{name}` | {} | {} | {} | {} | {} |",
            summary.files,
            summary.ghostline_serialized,
            summary.serialize_data_equal,
            summary.ghostline_from_wolvenkit_exact_original,
            summary.deserialize_data_equal
        )
        .unwrap();
    }

    writeln!(output, "\n## Representative divergences\n").unwrap();
    for (phase, examples) in &report.examples {
        writeln!(output, "### `{phase}`\n").unwrap();
        for example in examples {
            let root_type = example.root_type.as_deref().unwrap_or("<unknown>");
            writeln!(
                output,
                "- `{}` / `{}` / `{root_type}`: {}",
                example.archive,
                example.name_hash,
                example.detail.replace(['\r', '\n', '|'], " ")
            )
            .unwrap();
        }
        output.push('\n');
    }
    output
}

fn percent(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        return "n/a".to_owned();
    }
    let hundredths =
        (u128::from(numerator) * 10_000 + u128::from(denominator) / 2) / u128::from(denominator);
    format!("{}.{:02}%", hundredths / 100, hundredths % 100)
}

fn truncate(value: &str, maximum: usize) -> String {
    let mut chars = value.chars();
    let mut output = chars.by_ref().take(maximum).collect::<String>();
    if chars.next().is_some() {
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{percent, truncate};

    #[test]
    fn truncation_respects_character_boundaries() {
        assert_eq!(truncate("aé日", 2), "aé…");
        assert_eq!(truncate("short", 10), "short");
    }

    #[test]
    fn percentage_handles_empty_denominator() {
        assert_eq!(percent(1, 4), "25.00%");
        assert_eq!(percent(0, 0), "n/a");
    }
}

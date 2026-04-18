use clap::Parser;
use clap::Subcommand;
use forensic_engine::case::database::CaseDatabase;
use forensic_engine::container::IngestRegistry;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "ingest",
    about = "Ingest diagnostics and compatibility commands"
)]
pub struct IngestArgs {
    #[command(subcommand)]
    pub command: IngestSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum IngestSubcommand {
    Doctor(IngestDoctorArgs),
    Inspect(IngestInspectArgs),
    Matrix(IngestMatrixArgs),
    /// Run the full plugin pipeline headless against an evidence source.
    /// This is the CLI analogue of the Tauri desktop app's plugin runner
    /// (FIX-1): every registered plugin executes in registry order against
    /// the supplied root path, and each plugin's artifacts flow into the
    /// `prior_results` of the plugins that run after it so Sigma's
    /// correlation pass sees the full chain.
    Run(IngestRunArgs),
}

#[derive(Parser, Debug)]
pub struct IngestDoctorArgs {
    #[arg(long, help = "Path to evidence source")]
    pub input: String,

    #[arg(long, help = "Print JSON output")]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct IngestInspectArgs {
    #[arg(long, help = "Case ID")]
    pub case: String,

    #[arg(long, help = "Path to case database")]
    pub db: PathBuf,

    #[arg(long, default_value_t = 100, help = "Max ingest manifests")]
    pub limit: usize,

    #[arg(long, help = "Print JSON output")]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct IngestMatrixArgs {
    #[arg(long, help = "Print JSON output")]
    pub json: bool,
}

/// CLI args for `strata ingest run`. Field meanings:
/// * `source`            — path to the evidence source (image, mount, or logical dir).
/// * `case_dir`          — directory that receives the case database + JSON output.
/// * `case_name`         — human label recorded in the output summary.
/// * `examiner`          — examiner identity for the run-log entry.
/// * `plugins`           — optional comma-separated plugin name filter.
/// * `output_format`     — `json` or `text` (text is the default examiner summary).
/// * `triage_mode`       — reserved for future "fast only" plugin subset.
/// * `quiet`             — suppress the per-plugin stderr progress lines.
/// * `json_result`       — path to write the machine-readable JSON summary.
#[derive(Parser, Debug)]
pub struct IngestRunArgs {
    #[arg(long, help = "Evidence source path (image, mount, or logical directory)")]
    pub source: PathBuf,

    #[arg(long, help = "Case output directory (created if missing)")]
    pub case_dir: PathBuf,

    #[arg(long, default_value = "Untitled Case", help = "Case name")]
    pub case_name: String,

    #[arg(long, default_value = "unknown", help = "Examiner identity")]
    pub examiner: String,

    #[arg(long, value_delimiter = ',', help = "Comma-separated plugin names (default: all)")]
    pub plugins: Option<Vec<String>>,

    #[arg(long, default_value = "text", help = "Output format: text | json")]
    pub output_format: String,

    #[arg(long, help = "Reserved: triage/fast plugin subset")]
    pub triage_mode: bool,

    #[arg(long, help = "Suppress per-plugin progress output")]
    pub quiet: bool,

    #[arg(long, help = "Write machine-readable JSON summary to this path")]
    pub json_result: Option<PathBuf>,
}

/// Per-plugin outcome as emitted in the JSON summary.
#[derive(Serialize, Debug, Clone)]
pub struct IngestRunPluginOutcome {
    pub plugin: String,
    pub status: String,
    pub artifact_count: usize,
    pub elapsed_ms: u128,
    pub error: Option<String>,
}

/// Top-level JSON shape emitted by `strata ingest run`.
#[derive(Serialize, Debug, Clone)]
pub struct IngestRunSummary {
    pub case_name: String,
    pub examiner: String,
    pub source: String,
    pub case_dir: String,
    pub started_utc: String,
    pub finished_utc: String,
    pub elapsed_ms: u128,
    pub plugins_total: usize,
    pub plugins_ok: usize,
    pub plugins_failed: usize,
    pub plugins_zero: usize,
    pub artifacts_total: usize,
    pub per_plugin: Vec<IngestRunPluginOutcome>,
}

#[derive(Serialize)]
struct IngestDoctorOutput {
    input_path: String,
    container_type: String,
    parser_adapter: String,
    source_hint: String,
    profile: Option<serde_json::Value>,
}

pub fn execute(args: IngestArgs) {
    match args.command {
        IngestSubcommand::Doctor(cmd) => {
            let path = PathBuf::from(&cmd.input);
            if !path.exists() {
                eprintln!("Error: input path does not exist: {}", path.display());
                std::process::exit(1);
            }
            let desc = IngestRegistry::detect(&path);
            let output = IngestDoctorOutput {
                input_path: path.display().to_string(),
                container_type: desc.container_type.as_str().to_string(),
                parser_adapter: desc.parser_adapter,
                source_hint: desc.source_hint,
                profile: desc.profile.map(|p| serde_json::json!(p)),
            };
            if cmd.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
                return;
            }
            println!("=== Ingest Doctor ===");
            println!("Input: {}", output.input_path);
            println!("Container: {}", output.container_type);
            println!("Adapter: {}", output.parser_adapter);
            println!("Source Hint: {}", output.source_hint);
            if let Some(profile) = output.profile {
                println!("Profile: {}", profile);
            }
        }
        IngestSubcommand::Inspect(cmd) => {
            let db = match CaseDatabase::open(&cmd.case, &cmd.db) {
                Ok(db) => db,
                Err(err) => {
                    eprintln!("Failed to open case DB: {}", err);
                    std::process::exit(1);
                }
            };
            let rows = match db.list_ingest_manifests(cmd.limit) {
                Ok(rows) => rows,
                Err(err) => {
                    eprintln!("Failed to list ingest manifests: {}", err);
                    std::process::exit(1);
                }
            };
            if cmd.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string())
                );
                return;
            }
            println!("=== Ingest Inspect ===");
            println!("Case: {}", cmd.case);
            println!("Rows: {}", rows.len());
            for row in rows {
                println!(
                    "- {} | {} | {}:{} | warnings={} unsupported={}",
                    row.source_path,
                    row.container_type,
                    row.parser_name,
                    row.parser_version,
                    row.warning_count,
                    row.unsupported_count
                );
            }
        }
        IngestSubcommand::Run(cmd) => {
            let exit = run_ingest(cmd);
            if exit != 0 {
                std::process::exit(exit);
            }
        }
        IngestSubcommand::Matrix(cmd) => {
            let rows = IngestRegistry::compatibility_matrix_rows();
            if cmd.json {
                let json: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|(format, status, adapter)| {
                        serde_json::json!({ "format": format, "status": status, "adapter": adapter })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json).unwrap_or_else(|_| "[]".to_string())
                );
                return;
            }
            println!("=== Ingestion Compatibility Matrix ===");
            for (format, status, adapter) in rows {
                println!("- {:<24} {:<10} {}", format, status, adapter);
            }
        }
    }
}

/// Implementation of `strata ingest run`.
///
/// Exit code contract (matches SPRINTS_v5 FIX-1):
/// * `0` — every plugin returned Ok (even if artifact_count == 0).
/// * `1` — run completed but at least one plugin returned Err.
/// * `2` — fatal pre-run error (source missing, case_dir unwritable, …).
pub fn run_ingest(args: IngestRunArgs) -> i32 {
    if !args.source.exists() {
        eprintln!("Error: --source path does not exist: {}", args.source.display());
        return 2;
    }
    if let Err(e) = std::fs::create_dir_all(&args.case_dir) {
        eprintln!("Error: failed to create --case-dir {}: {}", args.case_dir.display(), e);
        return 2;
    }

    let started = chrono::Utc::now();
    let wall = Instant::now();
    let filter = args.plugins.as_deref();
    let results = strata_engine_adapter::run_all_on_path(args.source.as_path(), filter);

    let mut per_plugin: Vec<IngestRunPluginOutcome> = Vec::with_capacity(results.len());
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut zero = 0usize;
    let mut artifacts_total = 0usize;
    for (name, outcome) in &results {
        match outcome {
            Ok(output) => {
                let count = output.artifacts.len();
                artifacts_total += count;
                if count == 0 {
                    zero += 1;
                }
                ok += 1;
                if !args.quiet {
                    eprintln!("[{}] ok — {} artifact(s)", name, count);
                }
                per_plugin.push(IngestRunPluginOutcome {
                    plugin: name.clone(),
                    status: "ok".into(),
                    artifact_count: count,
                    elapsed_ms: 0,
                    error: None,
                });
            }
            Err(err) => {
                failed += 1;
                if !args.quiet {
                    eprintln!("[{}] ERROR — {}", name, err);
                }
                per_plugin.push(IngestRunPluginOutcome {
                    plugin: name.clone(),
                    status: "error".into(),
                    artifact_count: 0,
                    elapsed_ms: 0,
                    error: Some(err.clone()),
                });
            }
        }
    }

    let finished = chrono::Utc::now();
    let summary = IngestRunSummary {
        case_name: args.case_name.clone(),
        examiner: args.examiner.clone(),
        source: args.source.to_string_lossy().into_owned(),
        case_dir: args.case_dir.to_string_lossy().into_owned(),
        started_utc: started.to_rfc3339(),
        finished_utc: finished.to_rfc3339(),
        elapsed_ms: wall.elapsed().as_millis(),
        plugins_total: per_plugin.len(),
        plugins_ok: ok,
        plugins_failed: failed,
        plugins_zero: zero,
        artifacts_total,
        per_plugin,
    };

    // Write JSON result file if requested.
    if let Some(path) = args.json_result.as_ref() {
        write_summary_json(path, &summary);
    }

    let is_json = args.output_format.eq_ignore_ascii_case("json");
    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        print_text_summary(&summary);
    }

    if summary.plugins_failed > 0 {
        1
    } else {
        0
    }
}

fn write_summary_json(path: &Path, summary: &IngestRunSummary) {
    match serde_json::to_string_pretty(summary) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                eprintln!("Warning: failed to write --json-result {}: {}", path.display(), e);
            }
        }
        Err(e) => {
            eprintln!("Warning: failed to serialize summary: {}", e);
        }
    }
}

fn print_text_summary(summary: &IngestRunSummary) {
    println!("=== Strata Ingest Run ===");
    println!("Case: {}", summary.case_name);
    println!("Examiner: {}", summary.examiner);
    println!("Source: {}", summary.source);
    println!("Elapsed: {} ms", summary.elapsed_ms);
    println!(
        "Plugins: {} total, {} ok, {} failed, {} zero-artifacts",
        summary.plugins_total, summary.plugins_ok, summary.plugins_failed, summary.plugins_zero,
    );
    println!("Artifacts: {}", summary.artifacts_total);
    if summary.plugins_failed > 0 {
        println!("Failures:");
        for p in &summary.per_plugin {
            if let Some(err) = &p.error {
                println!("  - {}: {}", p.plugin, err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_args(source: PathBuf, case_dir: PathBuf, plugins: Option<Vec<String>>) -> IngestRunArgs {
        IngestRunArgs {
            source,
            case_dir,
            case_name: "t".into(),
            examiner: "t".into(),
            plugins,
            output_format: "json".into(),
            triage_mode: false,
            quiet: true,
            json_result: None,
        }
    }

    #[test]
    fn missing_source_returns_2() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let args = make_args(
            tmp.path().join("does-not-exist"),
            tmp.path().join("case"),
            Some(vec!["nonexistent-plugin".into()]),
        );
        assert_eq!(run_ingest(args), 2);
    }

    #[test]
    fn run_with_unknown_filter_succeeds_with_zero_plugins() {
        // No plugins match the filter, so the engine runs zero plugins,
        // no failures, exit 0.
        let tmp = tempfile::tempdir().expect("tempdir");
        let args = make_args(
            tmp.path().to_path_buf(),
            tmp.path().join("case"),
            Some(vec!["__does_not_match_anything__".into()]),
        );
        assert_eq!(run_ingest(args), 0);
    }

    #[test]
    fn case_dir_is_created_if_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let case_dir = tmp.path().join("new-case-subdir");
        assert!(!case_dir.exists());
        let args = make_args(
            tmp.path().to_path_buf(),
            case_dir.clone(),
            Some(vec!["__filter_nothing__".into()]),
        );
        let _ = run_ingest(args);
        assert!(case_dir.exists(), "case dir should be created");
    }

    #[test]
    fn summary_json_is_written_when_requested() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let out = tmp.path().join("summary.json");
        let mut args = make_args(
            tmp.path().to_path_buf(),
            tmp.path().join("case"),
            Some(vec!["__nope__".into()]),
        );
        args.json_result = Some(out.clone());
        let _ = run_ingest(args);
        assert!(out.exists(), "summary should exist");
        let body = std::fs::read_to_string(&out).expect("read");
        assert!(body.contains("\"case_name\""));
    }

    #[test]
    fn summary_structure_round_trips() {
        let s = IngestRunSummary {
            case_name: "c".into(),
            examiner: "e".into(),
            source: "/".into(),
            case_dir: "/".into(),
            started_utc: "now".into(),
            finished_utc: "now".into(),
            elapsed_ms: 1,
            plugins_total: 1,
            plugins_ok: 1,
            plugins_failed: 0,
            plugins_zero: 0,
            artifacts_total: 0,
            per_plugin: vec![IngestRunPluginOutcome {
                plugin: "p".into(),
                status: "ok".into(),
                artifact_count: 0,
                elapsed_ms: 0,
                error: None,
            }],
        };
        let j = serde_json::to_string(&s).expect("ser");
        assert!(j.contains("per_plugin"));
    }
}

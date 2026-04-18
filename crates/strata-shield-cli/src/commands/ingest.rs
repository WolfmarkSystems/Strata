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
///
/// * `source` — evidence source (image, mount, or logical dir).
/// * `case_dir` — case output directory.
/// * `case_name` — human label for the summary.
/// * `examiner` — examiner identity for the run-log entry.
/// * `plugins` — optional plugin name filter.
/// * `output_format` — `json` or `text`.
/// * `triage_mode` — reserved for "fast only" plugin subset.
/// * `quiet` — suppress per-plugin progress.
/// * `json_result` — JSON summary output path.
/// * `auto_unpack` — UNPACK-3: recursively extract nested containers.
/// * `unpack_root` — extraction scratch dir.
/// * `skip_routing` — DETECT-2: run every plugin regardless of classification.
/// * `include` — DETECT-2: add optional plugins to the recommendation.
/// * `auto` — DETECT-2: accept auto-selected plugin set.
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

    #[arg(long, help = "Auto-unpack nested containers before running plugins (UNPACK-3)")]
    pub auto_unpack: bool,

    #[arg(long, help = "Extraction scratch dir (default: <case_dir>/unpacked)")]
    pub unpack_root: Option<PathBuf>,

    #[arg(long, help = "Skip DETECT-1 classification and run every plugin")]
    pub skip_routing: bool,

    #[arg(long, value_delimiter = ',', help = "Add optional plugins to the recommended set (DETECT-2)")]
    pub include: Option<Vec<String>>,

    #[arg(long, help = "Accept auto-selected plugin set without prompting (DETECT-2)")]
    pub auto: bool,
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
    /// UNPACK-3: summary of the auto-unpack pass. `None` means
    /// `--auto-unpack` was not requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unpack: Option<UnpackSummary>,
    /// DETECT-1/2: image classification + plugin recommendation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<ClassificationSummary>,
}

/// Machine-readable subset of `UnpackResult`. Full container trace +
/// warnings go in the JSON result so chain of custody can reconstruct
/// which layers Strata traversed.
#[derive(Serialize, Debug, Clone)]
pub struct UnpackSummary {
    pub enabled: bool,
    pub filesystem_root: String,
    pub containers_traversed: usize,
    pub total_bytes_extracted: u64,
    pub total_files_extracted: u64,
    pub elapsed_ms: u128,
    pub limits_hit: Vec<String>,
    pub warnings: Vec<String>,
}

/// DETECT-1/2: image classification passed through to the CLI JSON.
#[derive(Serialize, Debug, Clone)]
pub struct ClassificationSummary {
    pub image_type: String,
    pub confidence: f64,
    pub recommended: Vec<String>,
    pub optional: Vec<String>,
    pub unnecessary: Vec<String>,
    pub evidence: Vec<String>,
    pub examiner_override: bool,
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

    // UNPACK-3: optionally unwrap nested containers before handing the
    // filesystem root to the plugin pipeline.
    let mut effective_source = args.source.clone();
    let mut unpack_summary: Option<UnpackSummary> = None;
    if args.auto_unpack {
        let scratch = args
            .unpack_root
            .clone()
            .unwrap_or_else(|| args.case_dir.join("unpacked"));
        if let Err(e) = std::fs::create_dir_all(&scratch) {
            eprintln!("Warning: failed to create unpack root {}: {}", scratch.display(), e);
        }
        let engine = strata_fs::unpack::UnpackEngine::new(scratch.clone())
            .with_max_total_bytes(250 * 1024 * 1024 * 1024) // 250 GiB cap
            .with_max_file_count(20_000_000)
            .with_max_depth(5);
        match strata_fs::unpack::unpack(args.source.as_path(), &engine) {
            Ok(r) => {
                if !args.quiet {
                    eprintln!(
                        "[unpack] {} container(s), {} file(s), {} byte(s) in {}ms",
                        r.containers_traversed.len(),
                        r.total_files_extracted,
                        r.total_bytes_extracted,
                        r.elapsed.as_millis()
                    );
                }
                effective_source = r.filesystem_root.clone();
                unpack_summary = Some(UnpackSummary {
                    enabled: true,
                    filesystem_root: r.filesystem_root.to_string_lossy().into_owned(),
                    containers_traversed: r.containers_traversed.len(),
                    total_bytes_extracted: r.total_bytes_extracted,
                    total_files_extracted: r.total_files_extracted,
                    elapsed_ms: r.elapsed.as_millis(),
                    limits_hit: r
                        .limits_hit
                        .iter()
                        .map(|l| format!("{:?}", l))
                        .collect(),
                    warnings: r.warnings.iter().map(|w| format!("{:?}", w)).collect(),
                });
            }
            Err(e) => {
                eprintln!("Warning: auto-unpack failed: {} (continuing with original source)", e);
            }
        }
    }

    // DETECT-1/2: image classification. If --plugins is set the
    // examiner has explicitly chosen a filter; never override it. If
    // --skip-routing is set, fall through to the every-plugin path.
    // Otherwise classify and apply the recommendation.
    let mut classification_summary: Option<ClassificationSummary> = None;
    let explicit_filter = args.plugins.clone();
    let effective_filter: Option<Vec<String>> = if let Some(p) = explicit_filter.clone() {
        Some(p)
    } else if args.skip_routing {
        None
    } else {
        let cls = strata_core::detect::classify(effective_source.as_path());
        let mut recommended: Vec<String> = cls.recommended_plugins.clone();
        if let Some(extra) = &args.include {
            for e in extra {
                if !recommended.iter().any(|r| r.eq_ignore_ascii_case(e)) {
                    recommended.push(e.clone());
                }
            }
        }
        if !args.quiet {
            eprintln!(
                "[detect] {} (confidence {:.2}) — recommending {} plugin(s)",
                cls.image_type_label(),
                cls.confidence,
                recommended.len(),
            );
        }
        classification_summary = Some(ClassificationSummary {
            image_type: cls.image_type_label(),
            confidence: cls.confidence,
            recommended: recommended.clone(),
            optional: cls.optional_plugins.clone(),
            unnecessary: cls.unnecessary_plugins.clone(),
            evidence: cls.evidence_markers(),
            examiner_override: false,
        });
        // Confidence floor: if the classifier isn't sure, run every
        // plugin (per DETECT-1 spec — "better to over-run than miss").
        if cls.confidence < 0.30 {
            None
        } else {
            Some(recommended)
        }
    };

    let filter: Option<&[String]> = effective_filter.as_deref();
    // PERSIST-2: always persist artifacts to <case_dir>/artifacts.sqlite.
    let case_id_sanitised = args
        .case_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect::<String>();
    let case_id = if case_id_sanitised.is_empty() {
        "case".to_string()
    } else {
        case_id_sanitised
    };

    // E2E-1: if the effective source is a forensic image file, open it,
    // parse partitions, mount filesystems via the FS dispatcher, and
    // build a CompositeVfs. Plugins walk the mounted evidence through
    // `ctx.vfs` / `ctx.read_file` / `ctx.find_by_name`.
    let mounted_vfs: Option<std::sync::Arc<dyn strata_fs::vfs::VirtualFilesystem>> =
        if effective_source.is_file() {
            match strata_evidence::open_evidence(effective_source.as_path()) {
                Ok(image_box) => {
                    let image: std::sync::Arc<dyn strata_evidence::EvidenceImage> =
                        std::sync::Arc::from(image_box);
                    if !args.quiet {
                        eprintln!(
                            "[evidence] opened {} ({} bytes, format {})",
                            effective_source.display(),
                            image.size(),
                            image.format_name()
                        );
                    }
                    mount_partitions_composite(image.clone(), args.quiet)
                }
                Err(e) => {
                    eprintln!(
                        "Warning: open_evidence({}) failed: {e}; falling back to host fs",
                        effective_source.display()
                    );
                    None
                }
            }
        } else {
            None
        };

    // v12 bridge: when a VFS is mounted, materialize known forensic
    // targets to <case_dir>/extracted/ once up-front. All plugins
    // then see real evidence files through their existing std::fs
    // call sites, AND can additionally query the VFS directly through
    // ctx.vfs. This multiplies the v11 "only migrated plugins see
    // the VFS" result across all 26 plugins without per-plugin
    // surgery.
    let (results, scratch_root) = match mounted_vfs {
        Some(vfs) => {
            let scratch = args.case_dir.join("extracted");
            match strata_engine_adapter::materialize_targets(&vfs, &scratch) {
                Ok(report) => {
                    if !args.quiet {
                        eprintln!(
                            "[evidence] materialized {} files ({} bytes) to {}",
                            report.files_written,
                            report.bytes_written,
                            scratch.display()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Warning: materialize_targets failed: {e}");
                }
            }
            let r = strata_engine_adapter::run_all_with_persistence_vfs(
                scratch.as_path(),
                vfs,
                args.case_dir.as_path(),
                &case_id,
                filter,
            );
            (r, Some(scratch))
        }
        None => {
            let r = strata_engine_adapter::run_all_with_persistence(
                effective_source.as_path(),
                args.case_dir.as_path(),
                &case_id,
                filter,
            );
            (r, None)
        }
    };
    let _ = scratch_root;

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
        unpack: unpack_summary,
        classification: classification_summary,
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
            auto_unpack: false,
            unpack_root: None,
            skip_routing: true,
            include: None,
            auto: true,
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
    fn auto_unpack_populates_unpack_summary_in_json() {
        // UNPACK-3 end-to-end: a synthetic tar → unpack → classify →
        // plugin filter → JSON summary should include a non-None
        // `unpack` field.
        use std::io::Write;
        let tmp = tempfile::tempdir().expect("tmp");
        let tar_path = tmp.path().join("fake.tar");
        let file = std::fs::File::create(&tar_path).expect("mk");
        let mut b = tar::Builder::new(file);
        let body = b"hello";
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, "a.txt", &body[..]).expect("append");
        b.finish().expect("finish");
        drop(b);

        let out = tmp.path().join("summary.json");
        let mut args = make_args(
            tar_path.clone(),
            tmp.path().join("case"),
            Some(vec!["__no_match__".into()]),
        );
        args.auto_unpack = true;
        args.json_result = Some(out.clone());
        let _ = run_ingest(args);
        let body = std::fs::read_to_string(&out).expect("read");
        assert!(body.contains("\"unpack\""), "unpack summary should be present");
        assert!(body.contains("\"containers_traversed\""));
    }

    #[test]
    fn classification_summary_present_when_routing_enabled() {
        // DETECT-2 integration: classification block appears when
        // routing is on (no explicit --plugins, --skip-routing off).
        let tmp = tempfile::tempdir().expect("tmp");
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).expect("mk");
        let out = tmp.path().join("summary.json");
        let args = IngestRunArgs {
            source: src,
            case_dir: tmp.path().join("case"),
            case_name: "t".into(),
            examiner: "t".into(),
            plugins: None, // no explicit filter → routing engages
            output_format: "json".into(),
            triage_mode: false,
            quiet: true,
            json_result: Some(out.clone()),
            auto_unpack: false,
            unpack_root: None,
            skip_routing: false,
            include: None,
            auto: true,
        };
        let _ = run_ingest(args);
        let body = std::fs::read_to_string(&out).expect("read");
        assert!(body.contains("\"classification\""));
    }

    #[test]
    fn skip_routing_flag_omits_classification_summary() {
        let tmp = tempfile::tempdir().expect("tmp");
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).expect("mk");
        let out = tmp.path().join("summary.json");
        let args = IngestRunArgs {
            source: src,
            case_dir: tmp.path().join("case"),
            case_name: "t".into(),
            examiner: "t".into(),
            plugins: Some(vec!["__no_match__".into()]),
            output_format: "json".into(),
            triage_mode: false,
            quiet: true,
            json_result: Some(out.clone()),
            auto_unpack: false,
            unpack_root: None,
            skip_routing: true,
            include: None,
            auto: true,
        };
        let _ = run_ingest(args);
        let body = std::fs::read_to_string(&out).expect("read");
        assert!(!body.contains("\"classification\""));
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
            unpack: None,
            classification: None,
        };
        let j = serde_json::to_string(&s).expect("ser");
        assert!(j.contains("per_plugin"));
    }
}

/// E2E-1 — Given an opened evidence image, parse the MBR/GPT
/// partition table, mount each partition's filesystem via
/// `strata-fs::fs_dispatch::open_filesystem`, and compose the
/// mounted filesystems into a `CompositeVfs`. Returns `None` when the
/// image has no readable partitions (caller falls back to host-fs
/// mode). Unsupported filesystem types (APFS/HFS+/ext*/FAT today)
/// are logged and skipped rather than aborting the mount.
fn mount_partitions_composite(
    image: std::sync::Arc<dyn strata_evidence::EvidenceImage>,
    quiet: bool,
) -> Option<std::sync::Arc<dyn strata_fs::vfs::VirtualFilesystem>> {
    let mut composite = strata_fs::vfs::CompositeVfs::new();
    let mut mounted_count = 0usize;

    // Try GPT first, then fall back to MBR.
    let parts_gpt = strata_evidence::read_gpt(image.as_ref()).unwrap_or_default();
    let mut parts_mbr = Vec::new();
    if parts_gpt.is_empty() {
        parts_mbr = strata_evidence::read_mbr(image.as_ref()).unwrap_or_default();
    }

    let partitions: Vec<(u64, u64, String)> = if !parts_gpt.is_empty() {
        parts_gpt
            .iter()
            .map(|p| {
                (
                    p.offset_bytes,
                    p.size_bytes,
                    if p.name.is_empty() {
                        format!("part{}", p.index)
                    } else {
                        p.name.clone()
                    },
                )
            })
            .collect()
    } else if !parts_mbr.is_empty() {
        parts_mbr
            .iter()
            .map(|p| (p.offset_bytes, p.size_bytes, format!("part{}", p.index)))
            .collect()
    } else {
        // No partition table — try to mount as a single filesystem at offset 0.
        Vec::from([(0u64, image.size(), "fs0".to_string())])
    };

    for (offset, size, name) in partitions {
        if size == 0 {
            continue;
        }
        match strata_fs::fs_dispatch::open_filesystem(
            std::sync::Arc::clone(&image),
            offset,
            size,
        ) {
            Ok(walker) => {
                composite.mount(&name, std::sync::Arc::from(walker));
                mounted_count += 1;
                if !quiet {
                    eprintln!(
                        "[evidence] mounted {} at offset {} size {}",
                        name, offset, size
                    );
                }
            }
            Err(e) => {
                if !quiet {
                    eprintln!(
                        "[evidence] skipped {} at offset {}: {}",
                        name, offset, e
                    );
                }
            }
        }
    }

    if mounted_count == 0 {
        None
    } else {
        Some(std::sync::Arc::new(composite))
    }
}

// Extracted from main.rs — run_triage_session_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "triage-session",
    about = "Run replay/verify/watchpoint triage flow"
)]
pub struct TriageSessionArgs {
    #[arg(short, long)]
    pub case: Option<String>,

    #[arg(short, long)]
    pub db: Option<PathBuf>,

    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,

    #[arg(long = "no-watchpoints")]
    pub no_watchpoints: bool,

    #[arg(long = "no-replay")]
    pub no_replay: bool,

    #[arg(long = "no-verify")]
    pub no_verify: bool,

    #[arg(long)]
    pub strict: bool,

    #[arg(long = "bundle-dir", default_value = "exports/defensibility")]
    pub bundle_dir: String,

    #[arg(long = "no-bundle")]
    pub no_bundle: bool,

    #[arg(short = 's', long = "sample")]
    pub sample: Option<u64>,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: TriageSessionArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    let case_id = args.case.clone();
    let db_path = args.db.clone();
    let session_name = args.name.clone();
    let enable_watchpoints = !args.no_watchpoints;
    let run_replay = !args.no_replay;
    let run_verify = !args.no_verify;
    let strict = args.strict;
    let bundle_dir = args.bundle_dir.clone();
    let export_bundle = !args.no_bundle;
    let sample = args.sample;
    let json_result_path = args.json_result.clone();
    let quiet = args.quiet;

    let case_id = match case_id {
        Some(id) => id,
        None => {
            let err_msg = "Error: --case <id> is required".to_string();
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "triage-session",
                    original_args.clone(),
                    EXIT_VALIDATION,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("invalid_input")
                .with_hint("Provide --case <case_id> argument");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_VALIDATION);
        }
    };

    let db_path = match db_path {
        Some(p) => p,
        None => {
            let err_msg = "Error: --db <path> is required".to_string();
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "triage-session",
                    original_args.clone(),
                    EXIT_VALIDATION,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("invalid_input")
                .with_hint("Provide --db <path> argument");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_VALIDATION);
        }
    };

    let conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            let err_msg = format!("Error opening database: {}", e);
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "triage-session",
                    original_args.clone(),
                    EXIT_ERROR,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("database_error")
                .with_hint("Ensure the database file exists and is a valid SQLite database");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_ERROR);
        }
    };

    let verify_opts = forensic_engine::case::verify::VerifyOptions {
        verify_activity_hash_chain: true,
        verify_packet_manifests: true,
        verify_db_integrity: true,
        verify_read_models_rebuild: true,
        verify_timeline_idempotency: true,
        verify_fts_queue_empty: false,
        sample_limit: sample,
    };

    let replay_opts = forensic_engine::case::replay::ReplayOptions {
        fingerprint_tables: forensic_engine::case::replay::ReplayOptions::default()
            .fingerprint_tables,
        run_read_model_rebuild: true,
        run_fts_rebuild: true,
        fts_entities: vec![
            "notes".to_string(),
            "bookmarks".to_string(),
            "exhibits".to_string(),
        ],
        process_fts_queue: true,
        fts_queue_batch: sample.unwrap_or(5000),
        run_db_optimize: false,
        sample_limit: sample,
    };

    let options = TriageSessionOptions {
        enable_watchpoints,
        run_replay,
        run_verify,
        verify_options: verify_opts,
        replay_options: replay_opts,
        fail_on_violations: strict,
        allow_verify_warn: !strict,
        allow_replay_warn: !strict,
        export_bundle,
        bundle_dir,
    };

    use forensic_engine::case::triage_session::TriageSessionManager;
    use std::sync::{Arc, Mutex};

    let conn = Arc::new(Mutex::new(conn));
    let manager = TriageSessionManager::new(conn, case_id.clone());

    if !quiet {
        println!("Starting triage session for case: {}", case_id);
        if let Some(name) = &session_name {
            println!("Session name: {}", name);
        }
    }

    match manager.start_session(session_name.as_deref(), options) {
        Ok(result) => {
            if !quiet {
                println!();
                println!("=== Triage Session Results ===");
                println!("Session ID: {}", result.session_id);
                println!("Status: {:?}", result.status);
                println!("Violations: {}", result.violations_count);

                if let Some(replay_id) = result.replay_id {
                    println!("Replay ID: {}", replay_id);
                }
                if let Some(verify_id) = result.verification_id {
                    println!("Verification ID: {}", verify_id);
                }

                if let Some(bundle_path) = &result.bundle_path {
                    println!("Bundle path: {}", bundle_path);
                }
                if let Some(bundle_hash) = &result.bundle_hash_sha256 {
                    println!("Bundle manifest hash: {}", bundle_hash);
                }
            }

            let exit_code = match result.status {
                TriageSessionStatus::Pass => EXIT_OK,
                TriageSessionStatus::Warn => EXIT_OK,
                TriageSessionStatus::Fail => EXIT_ERROR,
                TriageSessionStatus::Running => EXIT_ERROR,
            };

            if let Some(ref json_path) = json_result_path {
                let mut steps_run = Vec::new();
                if enable_watchpoints {
                    steps_run.push("watchpoints".to_string());
                }
                if run_replay {
                    steps_run.push("replay".to_string());
                }
                if run_verify {
                    steps_run.push("verify".to_string());
                }
                if export_bundle {
                    steps_run.push("bundle".to_string());
                }

                let triage_data = serde_json::json!({
                    "case_id": case_id,
                    "db_path": db_path.to_string_lossy().to_string(),
                    "session_name": session_name,
                    "flags": {
                        "watchpoints": enable_watchpoints,
                        "replay": run_replay,
                        "verify": run_verify,
                        "strict": strict,
                        "bundle": export_bundle
                    },
                    "sample": sample,
                    "steps_run": steps_run,
                    "result": {
                        "session_id": result.session_id,
                        "status": format!("{:?}", result.status),
                        "violations_count": result.violations_count,
                        "replay_id": result.replay_id,
                        "verification_id": result.verification_id,
                        "bundle_path": result.bundle_path,
                        "bundle_hash_sha256": result.bundle_hash_sha256
                    }
                });

                let mut outputs_map = std::collections::HashMap::new();
                let mut sizes_map = std::collections::HashMap::new();

                if let Some(ref bundle_path) = result.bundle_path {
                    outputs_map.insert("bundle_zip".to_string(), Some(bundle_path.clone()));
                    if let Ok(meta) = strata_fs::metadata(bundle_path) {
                        sizes_map.insert("bundle_zip".to_string(), meta.len());
                    }
                }

                let envelope = CliResultEnvelope::new(
                    "triage-session",
                    original_args.clone(),
                    exit_code,
                    start_time.elapsed().as_millis() as u64,
                )
                .with_data(triage_data)
                .with_outputs(outputs_map)
                .with_sizes(sizes_map);

                if result.status == TriageSessionStatus::Warn {
                    let envelope =
                        envelope.warn("Triage session completed with warnings".to_string());
                    let _ = envelope.write_to_file(json_path);
                } else if result.status == TriageSessionStatus::Fail {
                    let envelope = envelope.error("Triage session failed".to_string());
                    let _ = envelope.write_to_file(json_path);
                } else {
                    let _ = envelope.write_to_file(json_path);
                }
            }

            std::process::exit(exit_code);
        }
        Err(e) => {
            let err_msg = format!("Error running triage session: {}", e);
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "triage-session",
                    original_args.clone(),
                    EXIT_ERROR,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("execution_error")
                .with_hint("Check database integrity and case validity");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_ERROR);
        }
    }
}

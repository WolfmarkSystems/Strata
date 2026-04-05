use crate::envelope::{CliResultEnvelope, EXIT_ERROR, EXIT_OK, EXIT_VALIDATION};
use clap::Parser;
use forensic_engine::case::verify::{verify_case, VerificationStatus, VerifyOptions};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "verify", about = "Verifies case integrity and hash chains")]
pub struct VerifyArgs {
    #[arg(short, long)]
    pub case: Option<String>,

    #[arg(short, long)]
    pub db: Option<PathBuf>,

    #[arg(short, long)]
    pub sample: Option<u64>,

    #[arg(short = 'f', long = "strict-fts")]
    pub strict_fts: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: VerifyArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let case_id = match args.case {
        Some(id) => id,
        None => {
            let err_msg = "Error: --case <id> is required".to_string();
            if let Some(ref json_path) = args.json_result {
                let envelope = CliResultEnvelope::new(
                    "verify",
                    original_args.clone(),
                    EXIT_VALIDATION,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("invalid_input")
                .with_hint("Provide --case <case_id> argument");
                let _ = envelope.write_to_file(json_path);
            }
            if !args.quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_VALIDATION);
        }
    };

    let db_path = match args.db {
        Some(path) => path,
        None => {
            let err_msg = "Error: --db <path> is required".to_string();
            if let Some(ref json_path) = args.json_result {
                let envelope = CliResultEnvelope::new(
                    "verify",
                    original_args.clone(),
                    EXIT_VALIDATION,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("invalid_input")
                .with_hint("Provide --db <path> argument");
                let _ = envelope.write_to_file(json_path);
            }
            if !args.quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_VALIDATION);
        }
    };

    let verify_opts = VerifyOptions {
        verify_activity_hash_chain: true,
        verify_packet_manifests: true,
        verify_db_integrity: true,
        verify_read_models_rebuild: true,
        verify_timeline_idempotency: true,
        verify_fts_queue_empty: args.strict_fts,
        sample_limit: args.sample,
    };

    let elapsed_ms = start_time.elapsed().as_millis() as u64;

    match verify_case(&case_id, &db_path, verify_opts) {
        Ok(report) => {
            let exit_code = match report.status {
                VerificationStatus::Pass => EXIT_OK,
                VerificationStatus::Warn => EXIT_OK,
                VerificationStatus::Fail => EXIT_ERROR,
                VerificationStatus::Missing => EXIT_ERROR,
            };

            if !args.quiet {
                println!("\n=== Case Verification Report ===");
                println!("Case: {}", report.case_id);
                println!("Tool Version: {}", report.tool_version);
                println!("Schema Version: {}", report.schema_version);
                println!("Status: {:?}", report.status);
                println!();
                println!("Checks:");
                for check in &report.checks {
                    let status_str = match check.status {
                        VerificationStatus::Pass => "PASS",
                        VerificationStatus::Warn => "WARN",
                        VerificationStatus::Fail => "FAIL",
                        VerificationStatus::Missing => "MISSING",
                    };
                    println!("  [{}] {}: {}", status_str, check.name, check.message);
                }
                println!();
                println!("Stats:");
                println!(
                    "  Activity events checked: {}",
                    report.stats.activity_events_checked
                );
                println!("  Packets checked: {}", report.stats.packets_checked);
                println!("  Exhibits checked: {}", report.stats.exhibits_checked);
                println!(
                    "  Timeline events checked: {}",
                    report.stats.timeline_events_checked
                );
                println!("  FTS queue depth: {}", report.stats.fts_queue_depth);
                println!();
            }

            if let Some(json_path) = args.json_result {
                let checks_json: Vec<serde_json::Value> = report
                    .checks
                    .iter()
                    .map(|c| {
                        let status_str = match c.status {
                            VerificationStatus::Pass => "pass",
                            VerificationStatus::Warn => "warn",
                            VerificationStatus::Fail => "fail",
                            VerificationStatus::Missing => "missing",
                        };
                        serde_json::json!({
                            "name": c.name,
                            "status": status_str,
                            "message": c.message
                        })
                    })
                    .collect();

                let data = serde_json::json!({
                    "case_id": report.case_id,
                    "schema_version": report.schema_version,
                    "tool_version": report.tool_version,
                    "status": format!("{:?}", report.status).to_lowercase(),
                    "checks": checks_json,
                    "stats": {
                        "activity_events_checked": report.stats.activity_events_checked,
                        "packets_checked": report.stats.packets_checked,
                        "exhibits_checked": report.stats.exhibits_checked,
                        "timeline_events_checked": report.stats.timeline_events_checked,
                        "fts_queue_depth": report.stats.fts_queue_depth,
                    }
                });

                let mut envelope =
                    CliResultEnvelope::new("verify", original_args, exit_code, elapsed_ms)
                        .with_data(data);

                if report.status == VerificationStatus::Warn {
                    envelope =
                        envelope.warn("Some verification checks produced warnings".to_string());
                }

                if let Err(e) = envelope.write_to_file(&json_path) {
                    eprintln!("Error writing JSON result: {}", e);
                }
            }

            std::process::exit(exit_code);
        }
        Err(e) => {
            let err_msg = format!("Verification failed: {}", e);

            let error_type = if err_msg.contains("no such table") || err_msg.contains("database") {
                "database_error"
            } else if err_msg.contains("open") || err_msg.contains("IO") {
                "io_error"
            } else {
                "error"
            };

            if !args.quiet {
                println!("{}", err_msg);
            }

            if let Some(json_path) = args.json_result {
                let envelope =
                    CliResultEnvelope::new("verify", original_args, EXIT_ERROR, elapsed_ms)
                        .error(err_msg)
                        .with_error_type(error_type)
                        .with_hint("Check database path and case ID");
                if let Err(e) = envelope.write_to_file(&json_path) {
                    eprintln!("Error writing JSON result: {}", e);
                }
            }

            std::process::exit(EXIT_ERROR);
        }
    }
}

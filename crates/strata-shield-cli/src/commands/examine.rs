// Extracted from main.rs - run_examine_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "examine", about = "Run examination workflow for a case")]
pub struct ExamineArgs {
    #[arg(short, long)]
    pub case: Option<String>,

    #[arg(short, long)]
    pub db: Option<PathBuf>,

    #[arg(short = 'p', long = "preset", default_value = "Standard Examiner")]
    pub preset: String,

    #[arg(short = 'o', long = "override-json")]
    pub override_json: Option<PathBuf>,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: ExamineArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let case_id = args.case;
    let db_path = args.db;
    let preset_name = args.preset;
    let override_json_path = args.override_json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let case_id = match case_id {
        Some(id) => id,
        None => {
            let err_msg = "Error: --case <id> is required".to_string();
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "examine",
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
                    "examine",
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

    let overrides = if let Some(ref path) = override_json_path {
        read_json_file_with_limit::<serde_json::Value>(Path::new(path), CLI_OVERRIDE_JSON_MAX_BYTES)
            .ok()
    } else {
        None
    };

    if !quiet {
        println!("Starting examination for case: {}", case_id);
        println!("Using preset: {}", preset_name);
    }

    let conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            let err_msg = format!("Error opening database: {}", e);
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "examine",
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
    init_default_presets(&conn).ok();

    let db = match CaseDatabase::open(&case_id, &db_path) {
        Ok(db) => db,
        Err(e) => {
            let err_msg = format!("Error opening database: {}", e);
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "examine",
                    original_args.clone(),
                    EXIT_ERROR,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("database_error")
                .with_hint("Ensure the database file exists and case exists in database");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_ERROR);
        }
    };

    match start_examination(&db, &case_id, &preset_name, overrides) {
        Ok(result) => {
            if !quiet {
                println!();
                println!("=== Examination Complete ===");
                println!("Session ID: {}", result.session_id);
                println!("Status: {:?}", result.status);
                println!("Violations: {}", result.violations_count);

                if let Some(path) = &result.bundle_path {
                    println!("Bundle: {}", path);
                }
                if let Some(hash) = &result.bundle_hash_sha256 {
                    println!("Bundle Hash: {}", hash);
                }
            }

            let exit_code = match result.status {
                TriageSessionStatus::Pass | TriageSessionStatus::Running => EXIT_OK,
                TriageSessionStatus::Warn => EXIT_OK,
                TriageSessionStatus::Fail => EXIT_ERROR,
            };

            if let Some(ref json_path) = json_result_path {
                let examine_data = serde_json::json!({
                    "case_id": case_id,
                    "db_path": db_path.to_string_lossy().to_string(),
                    "preset_name": preset_name,
                    "override_json_path": override_json_path.map(|p| p.to_string_lossy().to_string()),
                    "invoked": "triage_session",
                    "result": {
                        "session_id": result.session_id,
                        "status": format!("{:?}", result.status),
                        "violations_count": result.violations_count,
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
                    "examine",
                    original_args.clone(),
                    exit_code,
                    start_time.elapsed().as_millis() as u64,
                )
                .with_data(examine_data)
                .with_outputs(outputs_map)
                .with_sizes(sizes_map);

                if result.status == TriageSessionStatus::Warn {
                    let envelope = envelope.warn("Examination completed with warnings".to_string());
                    let _ = envelope.write_to_file(json_path);
                } else if result.status == TriageSessionStatus::Fail {
                    let envelope = envelope.error("Examination failed".to_string());
                    let _ = envelope.write_to_file(json_path);
                } else {
                    let _ = envelope.write_to_file(json_path);
                }
            }

            std::process::exit(exit_code);
        }
        Err(e) => {
            let err_msg = format!("Error during examination: {}", e);

            let error_type = if e.to_string().contains("Preset not found") {
                "not_found"
            } else {
                "execution_error"
            };

            let hint = if e.to_string().contains("Preset not found") {
                "Run 'forensic_cli presets list' to see available presets"
            } else {
                "Check database integrity and case validity"
            };

            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "examine",
                    original_args.clone(),
                    EXIT_ERROR,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type(error_type)
                .with_hint(hint);
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_ERROR);
        }
    }
}

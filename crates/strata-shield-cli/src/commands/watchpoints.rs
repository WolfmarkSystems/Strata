// Extracted from main.rs - run_watchpoints_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "watchpoints",
    about = "Enable/disable/query integrity watchpoints"
)]
pub struct WatchpointsArgs {
    #[arg(short, long)]
    pub case: Option<String>,

    #[arg(short, long)]
    pub db: Option<PathBuf>,

    #[arg(long)]
    pub enable: bool,

    #[arg(long)]
    pub disable: bool,

    #[arg(long)]
    pub status: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: WatchpointsArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let case_id = args.case;
    let db_path = args.db;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let enable = if args.enable {
        Some(true)
    } else if args.disable {
        Some(false)
    } else {
        None
    };

    let case_id = match case_id {
        Some(id) => id,
        None => {
            let err_msg = "Error: --case <id> is required".to_string();
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "watchpoints",
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
                    "watchpoints",
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
                    "watchpoints",
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

    let action = if let Some(enabled) = enable {
        if enabled {
            "enable"
        } else {
            "disable"
        }
    } else {
        "status"
    }
    .to_string();

    let mut watchpoints_enabled: Option<bool> = None;
    let result = if let Some(enabled) = enable {
        match enable_integrity_watchpoints(&conn, &case_id, enabled) {
            Ok(_) => {
                watchpoints_enabled = Some(enabled);
                if !quiet {
                    println!(
                        "Integrity watchpoints {} for case {}",
                        if enabled { "enabled" } else { "disabled" },
                        case_id
                    );
                }
                Ok(())
            }
            Err(e) => {
                let err_msg = format!("Error setting watchpoints: {}", e);
                if let Some(ref json_path) = json_result_path {
                    let envelope = CliResultEnvelope::new(
                        "watchpoints",
                        original_args.clone(),
                        EXIT_ERROR,
                        start_time.elapsed().as_millis() as u64,
                    )
                    .error(err_msg.clone())
                    .with_error_type("database_error")
                    .with_hint("Check database integrity");
                    let _ = envelope.write_to_file(json_path);
                }
                if !quiet {
                    println!("{}", err_msg);
                }
                Err(e)
            }
        }
    } else {
        match get_integrity_watchpoints_enabled(&conn, &case_id) {
            Ok(enabled) => {
                watchpoints_enabled = Some(enabled);
                if !quiet {
                    println!(
                        "Integrity watchpoints for case {}: {}",
                        case_id,
                        if enabled { "ENABLED" } else { "DISABLED" }
                    );
                }
                Ok(())
            }
            Err(e) => {
                let err_msg = format!("Error getting watchpoints status: {}", e);
                if let Some(ref json_path) = json_result_path {
                    let envelope = CliResultEnvelope::new(
                        "watchpoints",
                        original_args.clone(),
                        EXIT_ERROR,
                        start_time.elapsed().as_millis() as u64,
                    )
                    .error(err_msg.clone())
                    .with_error_type("database_error")
                    .with_hint("Check database integrity");
                    let _ = envelope.write_to_file(json_path);
                }
                if !quiet {
                    println!("{}", err_msg);
                }
                Err(e)
            }
        }
    };

    if result.is_ok() {
        let violations_count = list_integrity_violations(&conn, &case_id, None, 1000)
            .ok()
            .map(|v| v.len() as u64);

        if let Some(ref json_path) = json_result_path {
            let watchpoints_data = serde_json::json!({
                "case_id": case_id,
                "db_path": db_path.to_string_lossy().to_string(),
                "action": action,
                "watchpoints_enabled": watchpoints_enabled,
                "integrity_violation_count": violations_count,
                "notes": serde_json::Value::Null
            });

            let envelope = CliResultEnvelope::new(
                "watchpoints",
                original_args.clone(),
                EXIT_OK,
                start_time.elapsed().as_millis() as u64,
            )
            .with_data(watchpoints_data);

            let _ = envelope.write_to_file(json_path);
        }

        std::process::exit(EXIT_OK);
    } else {
        std::process::exit(EXIT_ERROR);
    }
}

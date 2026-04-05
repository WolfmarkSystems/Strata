// Extracted from main.rs — run_violations_clear_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "violations-clear",
    about = "Clear integrity violations for a case"
)]
pub struct ViolationsClearArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn execute(args: ViolationsClearArgs) {
    let mut command_args = vec!["violations-clear".to_string()];
    command_args.extend(args.args);
    execute_legacy(command_args);
}

fn execute_legacy(mut args: Vec<String>) {
    let start_time = std::time::Instant::now();
    args.remove(0);

    let mut case_id: Option<String> = None;
    let mut db_path: Option<PathBuf> = None;
    let mut json_result_path: Option<PathBuf> = None;
    let mut quiet = false;
    let original_args = args.clone();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--case" | "-c" => {
                if i + 1 < args.len() {
                    case_id = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--db" | "-d" => {
                if i + 1 < args.len() {
                    db_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--json-result" => {
                if i + 1 < args.len() {
                    json_result_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--quiet" | "-q" => {
                quiet = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_help_and_exit();
            }
            _ => {
                i += 1;
            }
        }
    }

    let case_id = match case_id {
        Some(id) => id,
        None => {
            let err_msg = "Error: --case <id> is required".to_string();
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "violations-clear",
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
                    "violations-clear",
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
                    "violations-clear",
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

    match clear_integrity_violations(&conn, &case_id) {
        Ok(count) => {
            if !quiet {
                println!(
                    "Cleared {} integrity violations for case {}.",
                    count, case_id
                );
            }

            if let Some(ref json_path) = json_result_path {
                let clear_data = serde_json::json!({
                    "case_id": case_id,
                    "db_path": db_path.to_string_lossy().to_string(),
                    "cleared": count
                });

                let envelope = CliResultEnvelope::new(
                    "violations-clear",
                    original_args.clone(),
                    EXIT_OK,
                    start_time.elapsed().as_millis() as u64,
                )
                .with_data(clear_data);

                let _ = envelope.write_to_file(json_path);
            }

            std::process::exit(EXIT_OK);
        }
        Err(e) => {
            let err_msg = format!("Error clearing violations: {}", e);
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "violations-clear",
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
            std::process::exit(EXIT_ERROR);
        }
    }
}

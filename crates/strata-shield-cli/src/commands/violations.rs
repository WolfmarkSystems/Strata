// Extracted from main.rs - run_violations_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "violations", about = "List integrity violations for a case")]
pub struct ViolationsArgs {
    #[arg(short, long)]
    pub case: Option<String>,

    #[arg(short, long)]
    pub db: Option<PathBuf>,

    #[arg(short = 's', long = "since")]
    pub since: Option<String>,

    #[arg(short, long, default_value_t = 50u64)]
    pub limit: u64,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: ViolationsArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let case_id = args.case;
    let db_path = args.db;
    let since = args.since;
    let limit = args.limit;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let case_id = match case_id {
        Some(id) => id,
        None => {
            let err_msg = "Error: --case <id> is required".to_string();
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "violations",
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
                    "violations",
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
                    "violations",
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

    match list_integrity_violations(&conn, &case_id, since.clone(), limit) {
        Ok(violations) => {
            if violations.is_empty() {
                if !quiet {
                    println!("No integrity violations found for case {}.", case_id);
                    if let Some(s) = &since {
                        println!("  (since {})", s);
                    }
                }
            } else if !quiet {
                println!("=== Integrity Violations for Case {} ===", case_id);
                if let Some(s) = &since {
                    println!("Since: {}", s);
                }
                println!("Total: {} violations\n", violations.len());

                let mut by_table: std::collections::HashMap<String, Vec<_>> =
                    std::collections::HashMap::new();
                for v in &violations {
                    by_table.entry(v.table_name.clone()).or_default().push(v);
                }

                let mut tables: Vec<_> = by_table.keys().collect();
                tables.sort();

                for table in tables {
                    let table_violations = &by_table[table];
                    println!("{}: {} violation(s)", table, table_violations.len());

                    let mut ops: std::collections::HashMap<String, u64> =
                        std::collections::HashMap::new();
                    for v in table_violations {
                        *ops.entry(v.operation.clone()).or_insert(0) += 1;
                    }
                    for (op, count) in &ops {
                        println!("  - {}: {}", op, count);
                    }
                }

                println!("\nLatest violations (up to {}):", limit.min(10));
                for v in violations.iter().take(10) {
                    println!(
                        "  [{}] {} {} on {} by {:?} - {}",
                        v.occurred_utc,
                        v.operation,
                        v.table_name,
                        v.row_key.as_deref().unwrap_or("N/A"),
                        v.actor,
                        v.reason
                    );
                    if let Ok(details) = serde_json::from_str::<serde_json::Value>(&v.details_json)
                    {
                        if let Some(_case_id_val) = details.get("case_id") {
                            println!("       Details: {}", details);
                        }
                    }
                }
            }

            if let Some(ref json_path) = json_result_path {
                let violations_json: Vec<serde_json::Value> = violations
                    .iter()
                    .map(|v| {
                        serde_json::json!({
                            "id": v.id,
                            "case_id": v.case_id,
                            "occurred_utc": v.occurred_utc,
                            "table_name": v.table_name,
                            "operation": v.operation,
                            "row_key": v.row_key,
                            "actor": v.actor,
                            "reason": v.reason,
                            "details_json": v.details_json
                        })
                    })
                    .collect();

                let violations_data = serde_json::json!({
                    "case_id": case_id,
                    "db_path": db_path.to_string_lossy().to_string(),
                    "since_utc": since,
                    "limit": limit,
                    "total_returned": violations.len(),
                    "violations": violations_json
                });

                let envelope = CliResultEnvelope::new(
                    "violations",
                    original_args.clone(),
                    EXIT_OK,
                    start_time.elapsed().as_millis() as u64,
                )
                .with_data(violations_data);

                let _ = envelope.write_to_file(json_path);
            }

            std::process::exit(EXIT_OK);
        }
        Err(e) => {
            let err_msg = format!("Error listing violations: {}", e);
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "violations",
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

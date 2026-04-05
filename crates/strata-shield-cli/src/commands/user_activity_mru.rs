// Extracted from main.rs — run_user_activity_mru_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "user-activity-mru",
    about = "Parse user activity and MRU artifacts"
)]
pub struct UserActivityMruArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn execute(args: UserActivityMruArgs) {
    let mut command_args = vec!["user-activity-mru".to_string()];
    command_args.extend(args.args);
    execute_legacy(command_args);
}

fn execute_legacy(mut args: Vec<String>) {
    let start_time = std::time::Instant::now();
    args.remove(0);

    let mut input_path = env::var("FORENSIC_USER_ACTIVITY_MRU_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("exports").join("user_activity_mru.json"));
    let mut limit = USER_ACTIVITY_MRU_DEFAULT_LIMIT;
    let mut json_output = false;
    let mut json_result_path: Option<PathBuf> = None;
    let mut quiet = false;
    let original_args = args.clone();

    if let Some(json_idx) = args.iter().position(|arg| arg == "--json-result") {
        if json_idx + 1 < args.len() {
            json_result_path = Some(PathBuf::from(&args[json_idx + 1]));
        }
    }

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "--mru-input" | "--activity-input" => {
                if i + 1 < args.len() {
                    input_path = PathBuf::from(&args[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--limit" | "-l" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<usize>() {
                        Ok(parsed) => {
                            limit = parsed;
                            i += 2;
                        }
                        Err(_) => {
                            let err_msg = format!("Error: Invalid --limit '{}'", args[i + 1]);
                            if let Some(ref json_path) = json_result_path {
                                let envelope = CliResultEnvelope::new(
                                    "user-activity-mru",
                                    original_args.clone(),
                                    EXIT_VALIDATION,
                                    start_time.elapsed().as_millis() as u64,
                                )
                                .error(err_msg.clone())
                                .with_error_type("invalid_input")
                                .with_hint("Use --limit <N> with a numeric value");
                                let _ = envelope.write_to_file(json_path);
                            }
                            if !quiet {
                                eprintln!("{}", err_msg);
                            }
                            std::process::exit(EXIT_VALIDATION);
                        }
                    }
                } else {
                    i += 1;
                }
            }
            "--json" | "-j" => {
                json_output = true;
                i += 1;
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
                println!("User-Activity-MRU Command");
                println!("  --input <path>       User activity/MRU input path (json/csv/text)");
                println!("  --mru-input <path>   Alias for --input");
                println!("  --activity-input <path> Alias for --input");
                println!("  --limit <N>          Limit rows (default: 200, max: 5000)");
                println!("  --json               Print command payload as JSON");
                println!("  --json-result <file> Write envelope JSON to file");
                println!("  --quiet              Suppress console summary output");
                std::process::exit(EXIT_OK);
            }
            _ => {
                i += 1;
            }
        }
    }

    if limit == 0 {
        let err_msg = "Error: --limit must be greater than 0".to_string();
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "user-activity-mru",
                original_args.clone(),
                EXIT_VALIDATION,
                start_time.elapsed().as_millis() as u64,
            )
            .error(err_msg.clone())
            .with_error_type("invalid_input")
            .with_hint("Use a positive integer for --limit");
            let _ = envelope.write_to_file(json_path);
        }
        if !quiet {
            eprintln!("{}", err_msg);
        }
        std::process::exit(EXIT_VALIDATION);
    }

    let mut warnings: Vec<String> = Vec::new();
    if limit > USER_ACTIVITY_MRU_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, USER_ACTIVITY_MRU_MAX_LIMIT
        ));
        limit = USER_ACTIVITY_MRU_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct OutputRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let input_shape =
        forensic_engine::classification::user_activity_mru::detect_user_activity_mru_input_shape(
            &input_path,
        );
    let mut out_rows: Vec<OutputRow> = Vec::new();
    let mut primary_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    if input_path.exists() {
        let parsed_primary = parse_user_activity_mru_records_from_path(&input_path, limit);
        primary_rows = parsed_primary.len();
        let rows = if parsed_primary.is_empty() && input_path.is_file() {
            let parsed_fallback = forensic_engine::classification::user_activity_mru::parse_user_activity_mru_text_fallback(&input_path);
            fallback_rows = parsed_fallback.len();
            if fallback_rows == 0 {
                warnings.push(format!(
                    "No user-activity/MRU rows parsed from input: {}",
                    input_path.display()
                ));
            }
            parsed_fallback
        } else {
            parsed_primary
        };

        for row in rows {
            let ts = row.timestamp_unix;
            let output = serde_json::json!({
                "source": row.source,
                "event_type": row.event_type,
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc),
                "timestamp_precision": row.timestamp_precision,
                "command": row.command,
                "path": row.path,
                "program_name": row.program_name,
                "executable_name": row.executable_name,
                "mru_index": row.mru_index,
                "run_count": row.run_count,
                "user_sid": row.user_sid,
                "username": row.username,
                "source_path": row.source_path,
                "source_record_id": row.source_record_id,
                "severity": if row.run_count.unwrap_or_default() >= 10 { "warn" } else { "info" },
                "source_module": "user-activity-mru"
            });
            let key = format!(
                "{}|{}|{}|{}|{}",
                output["source"].as_str().unwrap_or(""),
                output["command"].as_str().unwrap_or(""),
                output["path"].as_str().unwrap_or(""),
                output["timestamp_unix"]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                output["source_record_id"].as_str().unwrap_or("")
            );
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(OutputRow {
                has_ts: output["timestamp_unix"].as_i64().is_some(),
                sort_ts: output["timestamp_unix"].as_i64().unwrap_or_default(),
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!(
            "User-activity input not found: {}",
            input_path.display()
        ));
    }

    if matches!(
        input_shape,
        forensic_engine::classification::user_activity_mru::UserActivityMruInputShape::Unknown
    ) {
        quality_flags.push("input_shape_unknown".to_string());
    }
    if fallback_rows > 0 {
        quality_flags.push("fallback_parser_used".to_string());
    }

    out_rows.sort_by(|a, b| {
        b.has_ts
            .cmp(&a.has_ts)
            .then_with(|| b.sort_ts.cmp(&a.sort_ts))
            .then_with(|| a.tie_key.cmp(&b.tie_key))
    });

    let timestamp_rows = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("timestamp_unix")
                .and_then(|v| v.as_i64())
                .is_some()
        })
        .count();
    let rows_with_executable = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("executable_name")
                .and_then(|v| v.as_str())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();
    let rows_with_command = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("command")
                .and_then(|v| v.as_str())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();
    let total_available = out_rows.len();
    let records = out_rows
        .into_iter()
        .take(limit)
        .map(|v| v.row)
        .collect::<Vec<_>>();

    let data = serde_json::json!({
        "input_path": input_path.to_string_lossy().to_string(),
        "input_exists": input_path.exists(),
        "limit": limit,
        "total_available": total_available,
        "total_returned": records.len(),
        "source_rows": {
            "primary": primary_rows,
            "fallback": fallback_rows
        },
        "summary": {
            "timestamp_rows": timestamp_rows,
            "rows_with_executable": rows_with_executable,
            "rows_with_command": rows_with_command,
            "warning_count": warnings.len()
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "user-activity-mru-normalized-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "source+command/path+timestamp+record",
            "timestamp_rows": timestamp_rows,
            "warning_count": warnings.len(),
            "quality_flags": quality_flags
        },
        "records": records
    });

    if json_output && !quiet {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else if !quiet {
        println!("=== User Activity / MRU ===");
        println!("Rows: primary={} fallback={}", primary_rows, fallback_rows);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "user-activity-mru",
            original_args.clone(),
            EXIT_OK,
            start_time.elapsed().as_millis() as u64,
        )
        .with_data(data);
        if !warnings.is_empty() {
            envelope = envelope.warn(warnings.join("; "));
        }
        let _ = envelope.write_to_file(json_path);
    }

    std::process::exit(EXIT_OK);
}

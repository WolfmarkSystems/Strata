// Extracted from main.rs — run_srum_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "srum", about = "Parse SRUM export records")]
pub struct SrumArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn execute(args: SrumArgs) {
    let mut command_args = vec!["srum".to_string()];
    command_args.extend(args.args);
    execute_legacy(command_args);
}

fn execute_legacy(mut args: Vec<String>) {
    let start_time = std::time::Instant::now();
    args.remove(0);

    let mut input_path = env::var("FORENSIC_SRUM_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_srum_path());
    let mut limit = SRUM_DEFAULT_LIMIT;
    let mut json_output = false;
    let mut json_result_path: Option<PathBuf> = None;
    let mut quiet = false;
    let original_args = args.clone();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
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
                                    "srum",
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
                println!("SRUM Command");
                println!("  --input <path>        SRUM export file path (JSON/CSV)");
                println!("  --limit <N>           Limit rows (default: 200, max: 5000)");
                println!("  --json                Print command payload as JSON");
                println!("  --json-result <file>  Write envelope JSON to file");
                println!("  --quiet               Suppress console summary output");
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
                "srum",
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
    if limit > SRUM_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, SRUM_MAX_LIMIT
        ));
        limit = SRUM_MAX_LIMIT;
    }

    if !input_path.exists() {
        let err_msg = format!("Error: SRUM input not found: {}", input_path.display());
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "srum",
                original_args.clone(),
                EXIT_VALIDATION,
                start_time.elapsed().as_millis() as u64,
            )
            .error(err_msg.clone())
            .with_error_type("invalid_input")
            .with_hint("Provide --input <path> to a SRUM export in JSON or CSV format");
            let _ = envelope.write_to_file(json_path);
        }
        if !quiet {
            eprintln!("{}", err_msg);
        }
        std::process::exit(EXIT_VALIDATION);
    }

    let raw = match strata_fs::read(&input_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            let err_msg = format!("Error reading SRUM input {}: {}", input_path.display(), e);
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "srum",
                    original_args.clone(),
                    EXIT_ERROR,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("io_error")
                .with_hint("Ensure the SRUM input path is readable");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                eprintln!("{}", err_msg);
            }
            std::process::exit(EXIT_ERROR);
        }
    };

    let parsed = parse_srum_records_with_metadata(&raw);
    let metadata = parsed.metadata.clone();
    let all_rows = parsed.records;
    if all_rows.is_empty() && !raw.is_empty() {
        warnings.push("No SRUM rows parsed from input.".to_string());
    }
    for flag in &metadata.quality_flags {
        warnings.push(format!("SRUM quality: {}", flag));
    }

    let with_timestamp_count = all_rows
        .iter()
        .filter(|r| r.timestamp_unix.is_some())
        .count();
    let with_sid_count = all_rows.iter().filter(|r| r.user_sid.is_some()).count();
    let with_exe_path_count = all_rows.iter().filter(|r| r.exe_path.is_some()).count();

    let total_available = all_rows.len();
    let records = all_rows
        .into_iter()
        .take(limit)
        .map(|row| {
            serde_json::json!({
                "record_id": row.record_id,
                "provider": row.provider,
                "record_type": row.record_type,
                "timestamp_utc": row.timestamp_utc,
                "timestamp_unix": row.timestamp_unix,
                "timestamp_precision": row.timestamp_precision,
                "app_id": row.app_id,
                "app_name": row.app_name,
                "exe_path": row.exe_path,
                "user_sid": row.user_sid,
                "network_interface": row.network_interface,
                "bytes_in": row.bytes_in,
                "bytes_out": row.bytes_out,
                "packets_in": row.packets_in,
                "packets_out": row.packets_out
            })
        })
        .collect::<Vec<_>>();

    let data = serde_json::json!({
        "input_path": input_path.to_string_lossy().to_string(),
        "input_exists": true,
        "limit": limit,
        "total_available": total_available,
        "total_returned": records.len(),
        "quality": {
            "input_shape": metadata.input_shape,
            "parser_mode": metadata.parser_mode,
            "fallback_used": metadata.fallback_used,
            "deduped_count": metadata.deduped_count,
            "quality_flags": metadata.quality_flags,
            "timestamp_rows": with_timestamp_count,
            "sid_rows": with_sid_count,
            "exe_path_rows": with_exe_path_count
        },
        "records": records
    });

    if json_output && !quiet {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else if !quiet {
        println!("=== SRUM Records ===");
        println!("Input: {}", input_path.display());
        println!("Total available: {}", total_available);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if let Some(rows) = data["records"].as_array() {
            for row in rows.iter().take(20) {
                let ts = row["timestamp_utc"].as_str().unwrap_or("n/a");
                let app = row["app_name"]
                    .as_str()
                    .or_else(|| row["app_id"].as_str())
                    .unwrap_or("unknown");
                let provider = row["provider"].as_str().unwrap_or("srum");
                println!("[{}] {} ({})", ts, app, provider);
            }
            if rows.len() > 20 {
                println!("... ({} more rows)", rows.len() - 20);
            }
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "srum",
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

// Extracted from main.rs — run_shimcache_deep_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "shimcache-deep", about = "Deep parser for ShimCache entries")]
pub struct ShimcacheDeepArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn execute(args: ShimcacheDeepArgs) {
    let mut command_args = vec!["shimcache-deep".to_string()];
    command_args.extend(args.args);
    execute_legacy(command_args);
}

fn execute_legacy(mut args: Vec<String>) {
    let start_time = std::time::Instant::now();
    args.remove(0);

    let mut appcompat_reg_path = PathBuf::from("exports").join("appcompat.reg");
    let mut limit = SHIMCACHE_DEEP_DEFAULT_LIMIT;
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
            "--appcompat-reg" | "--input" => {
                if i + 1 < args.len() {
                    appcompat_reg_path = PathBuf::from(&args[i + 1]);
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
                                    "shimcache-deep",
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
                println!("ShimCache-Deep Command");
                println!("  --appcompat-reg <path>  AppCompat/ShimCache .reg export path");
                println!("  --limit <N>             Limit records (default: 200, max: 5000)");
                println!("  --json                  Print command payload as JSON");
                println!("  --json-result <file>    Write envelope JSON to file");
                println!("  --quiet                 Suppress console summary output");
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
                "shimcache-deep",
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
    if limit > SHIMCACHE_DEEP_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, SHIMCACHE_DEEP_MAX_LIMIT
        ));
        limit = SHIMCACHE_DEEP_MAX_LIMIT;
    }

    let input_shape = detect_registry_input_shape(&appcompat_reg_path);
    let rows = if appcompat_reg_path.exists() {
        forensic_engine::classification::regbam::get_shim_cache_from_reg(&appcompat_reg_path)
    } else {
        warnings.push(format!(
            "ShimCache export not found: {}",
            appcompat_reg_path.display()
        ));
        Vec::new()
    };
    let total_available = rows.len();

    let records = rows
        .into_iter()
        .take(limit)
        .map(|row| {
            serde_json::json!({
                "path": row.path,
                "last_modified_unix": row.last_modified.map(|v| v as i64),
                "last_modified_utc": row.last_modified_utc,
                "timestamp_precision": if row.last_modified.is_some() { "seconds" } else { "none" },
                "source_key": row.source_key,
                "severity": "info",
                "executable_name": executable_name_from_hint(&row.path),
            })
        })
        .collect::<Vec<_>>();

    if records.is_empty() && appcompat_reg_path.exists() {
        warnings.push("No shim cache rows parsed from input.".to_string());
    }

    let timestamp_rows = records
        .iter()
        .filter(|row| {
            row.get("last_modified_unix")
                .and_then(|v| v.as_i64())
                .is_some()
        })
        .count();

    let data = serde_json::json!({
        "input_path": appcompat_reg_path.to_string_lossy().to_string(),
        "input_exists": appcompat_reg_path.exists(),
        "limit": limit,
        "total_available": total_available,
        "total_returned": records.len(),
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "reg-export",
            "fallback_used": false,
            "deduped_count": 0,
            "dedupe_reason": "path+timestamp",
            "timestamp_rows": timestamp_rows,
            "warning_count": warnings.len(),
            "quality_flags": Vec::<String>::new()
        },
        "entries": records
    });

    if json_output && !quiet {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else if !quiet {
        println!("=== ShimCache Deep Decode ===");
        println!("Input: {}", appcompat_reg_path.display());
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "shimcache-deep",
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

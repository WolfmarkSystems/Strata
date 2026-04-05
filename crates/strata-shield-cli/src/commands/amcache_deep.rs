// Extracted from main.rs — run_amcache_deep_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "amcache-deep", about = "Deep parser for Amcache artifacts")]
pub struct AmcacheDeepArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn execute(args: AmcacheDeepArgs) {
    let mut command_args = vec!["amcache-deep".to_string()];
    command_args.extend(args.args);
    execute_legacy(command_args);
}

fn execute_legacy(mut args: Vec<String>) {
    let start_time = std::time::Instant::now();
    args.remove(0);

    let mut amcache_reg_path = PathBuf::from("exports").join("amcache.reg");
    let mut limit = AMCACHE_DEEP_DEFAULT_LIMIT;
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
            "--amcache-reg" | "--input" => {
                if i + 1 < args.len() {
                    amcache_reg_path = PathBuf::from(&args[i + 1]);
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
                                    "amcache-deep",
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
                println!("Amcache-Deep Command");
                println!("  --amcache-reg <path>  Amcache .reg export path");
                println!("  --input <path>        Alias for --amcache-reg");
                println!("  --limit <N>           Limit records (default: 200, max: 5000)");
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
                "amcache-deep",
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
    if limit > AMCACHE_DEEP_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, AMCACHE_DEEP_MAX_LIMIT
        ));
        limit = AMCACHE_DEEP_MAX_LIMIT;
    }

    let input_shape = detect_registry_input_shape(&amcache_reg_path);
    let mut fallback_used = false;
    let mut fallback_rows = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();

    let mut parsed_rows = if amcache_reg_path.exists() {
        match forensic_engine::classification::amcache::get_amcache_file_entries_from_reg(
            &amcache_reg_path,
        ) {
            Ok(rows) => rows,
            Err(e) => {
                warnings.push(format!(
                    "Could not parse Amcache export {}: {}",
                    amcache_reg_path.display(),
                    e
                ));
                Vec::new()
            }
        }
    } else {
        warnings.push(format!(
            "Amcache export not found: {}",
            amcache_reg_path.display()
        ));
        Vec::new()
    };

    if parsed_rows.is_empty() && amcache_reg_path.exists() {
        if let Ok(raw) = strata_fs::read(&amcache_reg_path) {
            if let Ok(fallback) = forensic_engine::classification::amcache::parse_amcache(&raw) {
                if !fallback.is_empty() {
                    fallback_used = true;
                    fallback_rows = fallback.len();
                    parsed_rows = fallback;
                }
            }
        }
    }

    let mut deduped_count = 0usize;
    let mut by_key: std::collections::BTreeMap<
        String,
        forensic_engine::classification::amcache::AmCacheEntry,
    > = std::collections::BTreeMap::new();
    for row in parsed_rows {
        let ts = if row.last_modified > 0 {
            row.last_modified
        } else {
            row.created
        };
        let key = format!(
            "{}|{}|{}",
            row.file_path.to_ascii_lowercase(),
            row.sha1.clone().unwrap_or_default().to_ascii_uppercase(),
            ts
        );
        if by_key.insert(key, row).is_some() {
            deduped_count = deduped_count.saturating_add(1);
        }
    }

    let mut normalized_rows = by_key.into_values().collect::<Vec<_>>();
    normalized_rows.sort_by(|a, b| {
        let a_ts = if a.last_modified > 0 {
            a.last_modified as i64
        } else {
            a.created as i64
        };
        let b_ts = if b.last_modified > 0 {
            b.last_modified as i64
        } else {
            b.created as i64
        };
        b_ts.cmp(&a_ts)
            .then_with(|| {
                a.file_path
                    .to_ascii_lowercase()
                    .cmp(&b.file_path.to_ascii_lowercase())
            })
            .then_with(|| {
                a.sha1
                    .clone()
                    .unwrap_or_default()
                    .cmp(&b.sha1.clone().unwrap_or_default())
            })
    });

    if input_shape == RegistryInputShape::Unknown {
        quality_flags.push("input_shape_unknown".to_string());
    }

    let total_available = normalized_rows.len();
    let with_sha1_rows = normalized_rows
        .iter()
        .filter(|row| row.sha1.is_some())
        .count();
    let timestamp_rows = normalized_rows
        .iter()
        .filter(|row| row.last_modified > 0 || row.created > 0)
        .count();

    let entries = normalized_rows
        .into_iter()
        .take(limit)
        .map(|row| {
            let timestamp_unix = if row.last_modified > 0 {
                Some(row.last_modified as i64)
            } else if row.created > 0 {
                Some(row.created as i64)
            } else {
                None
            };
            let timestamp_utc = if row.last_modified > 0 {
                row.last_modified_utc.clone()
            } else {
                row.created_utc.clone()
            };
            serde_json::json!({
                "file_path": row.file_path,
                "sha1": row.sha1,
                "program_id": row.program_id,
                "last_modified_unix": if row.last_modified > 0 { Some(row.last_modified as i64) } else { None },
                "last_modified_utc": row.last_modified_utc,
                "created_unix": if row.created > 0 { Some(row.created as i64) } else { None },
                "created_utc": row.created_utc,
                "timestamp_unix": timestamp_unix,
                "timestamp_utc": timestamp_utc,
                "timestamp_precision": if timestamp_unix.is_some() { "seconds" } else { "none" },
                "severity": "info",
                "executable_name": executable_name_from_hint(&row.file_path),
            })
        })
        .collect::<Vec<_>>();

    let data = serde_json::json!({
        "input_path": amcache_reg_path.to_string_lossy().to_string(),
        "input_exists": amcache_reg_path.exists(),
        "limit": limit,
        "total_available": total_available,
        "total_returned": entries.len(),
        "summary": {
            "rows_with_sha1": with_sha1_rows,
            "timestamp_rows": timestamp_rows
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "reg-export-merge",
            "fallback_used": fallback_used,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "path+sha1+timestamp",
            "warning_count": warnings.len(),
            "quality_flags": quality_flags
        },
        "entries": entries
    });

    if json_output && !quiet {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else if !quiet {
        println!("=== Amcache Deep Decode ===");
        println!("Input: {}", amcache_reg_path.display());
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "amcache-deep",
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

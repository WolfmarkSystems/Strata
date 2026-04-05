// Extracted from main.rs — run_bam_dam_activity_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "bam-dam-activity", about = "Parse BAM/DAM execution activity")]
pub struct BamDamActivityArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn execute(args: BamDamActivityArgs) {
    let mut command_args = vec!["bam-dam-activity".to_string()];
    command_args.extend(args.args);
    execute_legacy(command_args);
}

fn execute_legacy(mut args: Vec<String>) {
    let start_time = std::time::Instant::now();
    args.remove(0);

    let mut bam_reg_path = PathBuf::from("exports").join("bam.reg");
    let mut limit = BAM_DAM_ACTIVITY_DEFAULT_LIMIT;
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
            "--bam-reg" | "--input" => {
                if i + 1 < args.len() {
                    bam_reg_path = PathBuf::from(&args[i + 1]);
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
                                    "bam-dam-activity",
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
                println!("BAM-DAM-Activity Command");
                println!("  --bam-reg <path>      BAM/DAM .reg export path");
                println!("  --input <path>        Alias for --bam-reg");
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
                "bam-dam-activity",
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
    if limit > BAM_DAM_ACTIVITY_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, BAM_DAM_ACTIVITY_MAX_LIMIT
        ));
        limit = BAM_DAM_ACTIVITY_MAX_LIMIT;
    }

    let input_shape = detect_registry_input_shape(&bam_reg_path);
    let mut fallback_used = false;
    let mut fallback_rows = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut rows = if bam_reg_path.exists() {
        forensic_engine::classification::regbam::get_bam_state_from_reg(&bam_reg_path)
    } else {
        warnings.push(format!(
            "BAM/DAM export not found: {}",
            bam_reg_path.display()
        ));
        Vec::new()
    };

    if rows.is_empty() && bam_reg_path.exists() {
        let fallback = parse_registry_text_fallback(&bam_reg_path, "bam-dam");
        if !fallback.is_empty() {
            fallback_used = true;
            fallback_rows = fallback.len();
            for item in fallback {
                let program_path = item
                    .get("value")
                    .and_then(|v| v.as_str())
                    .or_else(|| item.get("key").and_then(|v| v.as_str()))
                    .unwrap_or_default()
                    .to_string();
                if program_path.is_empty() {
                    continue;
                }
                rows.push(forensic_engine::classification::regbam::BamEntry {
                    program_path,
                    last_execution: None,
                    last_execution_utc: None,
                    actor_sid: None,
                    source: "bam".to_string(),
                });
            }
        }
    }

    if input_shape == RegistryInputShape::Unknown {
        quality_flags.push("input_shape_unknown".to_string());
    }

    let total_available = rows.len();

    let mut deduped_count = 0usize;
    let mut by_key: std::collections::BTreeMap<
        String,
        forensic_engine::classification::regbam::BamEntry,
    > = std::collections::BTreeMap::new();
    for row in rows {
        let key = format!(
            "{}|{}|{}",
            row.program_path.to_ascii_lowercase(),
            row.actor_sid
                .clone()
                .unwrap_or_default()
                .to_ascii_uppercase(),
            row.source.to_ascii_lowercase()
        );
        if let Some(existing) = by_key.get(&key) {
            if existing.last_execution.unwrap_or(0) >= row.last_execution.unwrap_or(0) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
        }
        by_key.insert(key, row);
    }

    let mut normalized_rows = by_key.into_values().collect::<Vec<_>>();
    normalized_rows.sort_by(|a, b| {
        b.last_execution
            .unwrap_or(0)
            .cmp(&a.last_execution.unwrap_or(0))
            .then_with(|| a.program_path.cmp(&b.program_path))
            .then_with(|| a.source.cmp(&b.source))
    });

    let bam_rows = normalized_rows
        .iter()
        .filter(|row| !row.source.eq_ignore_ascii_case("dam"))
        .count();
    let dam_rows = normalized_rows
        .iter()
        .filter(|row| row.source.eq_ignore_ascii_case("dam"))
        .count();
    let timestamp_rows = normalized_rows
        .iter()
        .filter(|row| row.last_execution.is_some())
        .count();

    let entries = normalized_rows
        .into_iter()
        .take(limit)
        .map(|row| {
            let source_kind = if row.source.eq_ignore_ascii_case("dam") {
                "dam"
            } else {
                "bam"
            };
            serde_json::json!({
                "program_path": row.program_path,
                "last_execution_unix": row.last_execution.map(|v| v as i64),
                "last_execution_utc": row.last_execution_utc,
                "actor_sid": row.actor_sid,
                "source_kind": source_kind,
                "severity": if source_kind == "dam" { "warn" } else { "info" },
                "executable_name": executable_name_from_hint(&row.program_path),
            })
        })
        .collect::<Vec<_>>();

    let data = serde_json::json!({
        "input_path": bam_reg_path.to_string_lossy().to_string(),
        "input_exists": bam_reg_path.exists(),
        "limit": limit,
        "total_available": total_available,
        "total_returned": entries.len(),
        "source_rows": {
            "bam": bam_rows,
            "dam": dam_rows
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "reg-export",
            "fallback_used": fallback_used,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "program+actor+source keep newest timestamp",
            "timestamp_rows": timestamp_rows,
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
        println!("=== BAM/DAM Activity ===");
        println!("Input: {}", bam_reg_path.display());
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "bam-dam-activity",
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

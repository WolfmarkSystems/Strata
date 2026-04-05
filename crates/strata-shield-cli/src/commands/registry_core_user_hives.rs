// Extracted from main.rs — run_registry_core_user_hives_command
// TODO: Convert to clap derive args in a future pass

use crate::*;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "registry-core-user-hives",
    about = "Extract forensic data from core user hives"
)]
pub struct RegistryCoreUserHivesArgs {
    #[arg(long, help = "RunMRU .reg export path")]
    pub runmru_reg: Option<PathBuf>,

    #[arg(long, help = "OpenSaveMRU .reg export path")]
    pub opensave_reg: Option<PathBuf>,

    #[arg(long, help = "UserAssist .reg export path")]
    pub userassist_reg: Option<PathBuf>,

    #[arg(long, help = "RecentDocs .reg export path")]
    pub recentdocs_reg: Option<PathBuf>,

    #[arg(short, long, help = "Limit records (default: 200, max: 5000)")]
    pub limit: Option<String>,

    #[arg(short, long, help = "Print command payload as JSON")]
    pub json: bool,

    #[arg(long, help = "Write envelope JSON to file")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long, help = "Suppress console summary output")]
    pub quiet: bool,
}

pub fn execute(args: RegistryCoreUserHivesArgs, _command_name: &str, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let runmru_reg_path = args
        .runmru_reg
        .unwrap_or_else(|| PathBuf::from("exports").join("runmru.reg"));
    let opensave_reg_path = args
        .opensave_reg
        .unwrap_or_else(|| PathBuf::from("exports").join("mru2.reg"));
    let userassist_reg_path = args
        .userassist_reg
        .unwrap_or_else(|| PathBuf::from("exports").join("userassist.reg"));
    let recentdocs_reg_path = args
        .recentdocs_reg
        .unwrap_or_else(|| PathBuf::from("exports").join("recentdocs.reg"));

    let mut limit = match args.limit {
        Some(limit_str) => match limit_str.parse::<usize>() {
            Ok(parsed) => parsed,
            Err(_) => {
                let err_msg = format!("Error: Invalid --limit '{}'", limit_str);
                if let Some(ref json_path) = json_result_path {
                    let envelope = crate::envelope::CliResultEnvelope::new(
                        "registry-core-user-hives",
                        original_args.clone(),
                        crate::envelope::EXIT_VALIDATION,
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
                std::process::exit(crate::envelope::EXIT_VALIDATION);
            }
        },
        None => crate::REGISTRY_CORE_HIVES_DEFAULT_LIMIT,
    };

    if limit == 0 {
        let err_msg = "Error: --limit must be greater than 0".to_string();
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "registry-core-user-hives",
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
    if limit > REGISTRY_CORE_HIVES_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, REGISTRY_CORE_HIVES_MAX_LIMIT
        ));
        limit = REGISTRY_CORE_HIVES_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct RegistryCoreRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let runmru_shape = detect_registry_input_shape(&runmru_reg_path);
    let opensave_shape = detect_registry_input_shape(&opensave_reg_path);
    let userassist_shape = detect_registry_input_shape(&userassist_reg_path);
    let recentdocs_shape = detect_registry_input_shape(&recentdocs_reg_path);

    let mut out_rows: Vec<RegistryCoreRow> = Vec::new();
    let mut runmru_count = 0usize;
    let mut opensave_count = 0usize;
    let mut userassist_count = 0usize;
    let mut recentdocs_count = 0usize;
    let mut deduped_count = 0usize;
    let mut fallback_rows = 0usize;
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut quality_flags: Vec<String> = Vec::new();

    if runmru_reg_path.exists() {
        let rows = forensic_engine::classification::regmru::get_run_mru_from_reg(&runmru_reg_path);
        for row in rows {
            runmru_count = runmru_count.saturating_add(1);
            let command = row.value.trim().trim_matches('"').replace('/', "\\");
            let output = serde_json::json!({
                "source": "runmru",
                "event_type": "runmru-command",
                "timestamp_unix": serde_json::Value::Null,
                "timestamp_utc": serde_json::Value::Null,
                "timestamp_precision": "none",
                "severity": "info",
                "index": row.index,
                "command": command,
                "executable_name": executable_name_from_command_text(&row.value),
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(RegistryCoreRow {
                has_ts: false,
                sort_ts: 0,
                tie_key: key,
                row: output,
            });
        }
        if runmru_count == 0 {
            let fallback = parse_registry_text_fallback(&runmru_reg_path, "runmru");
            fallback_rows = fallback_rows.saturating_add(fallback.len());
            for output in fallback {
                let key = powershell_record_dedupe_key(&output);
                if !seen_dedupe.insert(key.clone()) {
                    deduped_count = deduped_count.saturating_add(1);
                    continue;
                }
                out_rows.push(RegistryCoreRow {
                    has_ts: false,
                    sort_ts: 0,
                    tie_key: key,
                    row: output,
                });
            }
        }
    } else {
        warnings.push(format!(
            "RunMRU export not found: {}",
            runmru_reg_path.display()
        ));
    }

    if opensave_reg_path.exists() {
        let rows = forensic_engine::classification::regmru2::get_open_save_mru_from_reg(
            &opensave_reg_path,
        );
        for row in rows {
            opensave_count = opensave_count.saturating_add(1);
            let path = row.path.trim().trim_matches('"').replace('/', "\\");
            let output = serde_json::json!({
                "source": "opensave",
                "event_type": "opensave-path",
                "timestamp_unix": serde_json::Value::Null,
                "timestamp_utc": serde_json::Value::Null,
                "timestamp_precision": "none",
                "severity": "info",
                "name": row.name,
                "path": path,
                "executable_name": executable_name_from_hint(&row.path)
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(RegistryCoreRow {
                has_ts: false,
                sort_ts: 0,
                tie_key: key,
                row: output,
            });
        }
        if opensave_count == 0 {
            let fallback = parse_registry_text_fallback(&opensave_reg_path, "opensave");
            fallback_rows = fallback_rows.saturating_add(fallback.len());
            for output in fallback {
                let key = powershell_record_dedupe_key(&output);
                if !seen_dedupe.insert(key.clone()) {
                    deduped_count = deduped_count.saturating_add(1);
                    continue;
                }
                out_rows.push(RegistryCoreRow {
                    has_ts: false,
                    sort_ts: 0,
                    tie_key: key,
                    row: output,
                });
            }
        }
    } else {
        warnings.push(format!(
            "OpenSaveMRU export not found: {}",
            opensave_reg_path.display()
        ));
    }

    if userassist_reg_path.exists() {
        let rows = forensic_engine::classification::reguserassist::get_user_assist_from_reg(
            &userassist_reg_path,
        );
        for row in rows {
            userassist_count = userassist_count.saturating_add(1);
            let ts = row.last_run.map(|v| v as i64);
            let output = serde_json::json!({
                "source": "userassist",
                "event_type": "userassist-program",
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc),
                "timestamp_precision": if ts.is_some() { "seconds" } else { "none" },
                "severity": if row.run_count >= 10 { "warn" } else { "info" },
                "program_name": row.program_name.replace('/', "\\"),
                "run_count": row.run_count,
                "last_run_utc": row.last_run_utc,
                "executable_name": executable_name_from_hint(&row.program_name)
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(RegistryCoreRow {
                has_ts: ts.is_some(),
                sort_ts: ts.unwrap_or_default(),
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!(
            "UserAssist export not found: {}",
            userassist_reg_path.display()
        ));
    }

    if recentdocs_reg_path.exists() {
        let rows =
            forensic_engine::classification::regmru::get_recent_docs_from_reg(&recentdocs_reg_path);
        for row in rows {
            recentdocs_count = recentdocs_count.saturating_add(1);
            let ts = row.timestamp.map(|v| v as i64);
            let output = serde_json::json!({
                "source": "recentdocs",
                "event_type": "recent-doc",
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc),
                "timestamp_precision": if ts.is_some() { "seconds" } else { "none" },
                "severity": "info",
                "name": row.name.replace('/', "\\"),
                "executable_name": executable_name_from_hint(&row.name)
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(RegistryCoreRow {
                has_ts: ts.is_some(),
                sort_ts: ts.unwrap_or_default(),
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!(
            "RecentDocs export not found: {}",
            recentdocs_reg_path.display()
        ));
    }

    if runmru_shape == RegistryInputShape::Unknown
        || opensave_shape == RegistryInputShape::Unknown
        || userassist_shape == RegistryInputShape::Unknown
        || recentdocs_shape == RegistryInputShape::Unknown
    {
        quality_flags.push("one_or_more_inputs_have_unknown_shape".to_string());
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
    let executable_rows = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("executable_name")
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
        "limit": limit,
        "total_available": total_available,
        "total_returned": records.len(),
        "inputs": {
            "runmru_reg": runmru_reg_path.to_string_lossy().to_string(),
            "runmru_found": runmru_reg_path.exists(),
            "opensave_reg": opensave_reg_path.to_string_lossy().to_string(),
            "opensave_found": opensave_reg_path.exists(),
            "userassist_reg": userassist_reg_path.to_string_lossy().to_string(),
            "userassist_found": userassist_reg_path.exists(),
            "recentdocs_reg": recentdocs_reg_path.to_string_lossy().to_string(),
            "recentdocs_found": recentdocs_reg_path.exists()
        },
        "source_rows": {
            "runmru": runmru_count,
            "opensave": opensave_count,
            "userassist": userassist_count,
            "recentdocs": recentdocs_count
        },
        "quality": {
            "input_shapes": {
                "runmru": runmru_shape.as_str(),
                "opensave": opensave_shape.as_str(),
                "userassist": userassist_shape.as_str(),
                "recentdocs": recentdocs_shape.as_str(),
            },
            "parser_mode": "registry-export-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "source+timestamp+core_fields",
            "timestamp_rows": timestamp_rows,
            "executable_rows": executable_rows,
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
        println!("=== Registry Core User Hives ===");
        println!(
            "Rows: runmru={} opensave={} userassist={} recentdocs={}",
            runmru_count, opensave_count, userassist_count, recentdocs_count
        );
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "registry-core-user-hives",
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

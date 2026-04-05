// Extracted from main.rs — run_powershell_artifacts_command
// TODO: Convert to clap derive args in a future pass

use crate::*;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "powershell-artifacts",
    about = "Extract forensic data from PowerShell history, logs, events, and transcripts"
)]
pub struct PowershellArgs {
    #[arg(long, help = "ConsoleHost_history.txt path")]
    pub history: Option<PathBuf>,

    #[arg(long, help = "script_block.log path")]
    pub script_log: Option<PathBuf>,

    #[arg(long, help = "ps_events.json path")]
    pub events: Option<PathBuf>,

    #[arg(long, help = "transcript directory path")]
    pub transcripts_dir: Option<PathBuf>,

    #[arg(long, help = "modules inventory path")]
    pub modules: Option<PathBuf>,

    #[arg(short, long, help = "Limit records (default: 200, max: 5000)")]
    pub limit: Option<String>,

    #[arg(short, long, help = "Print command payload as JSON")]
    pub json: bool,

    #[arg(long, help = "Write envelope JSON to file")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long, help = "Suppress console summary output")]
    pub quiet: bool,
}

pub fn execute(args: PowershellArgs, _command_name: &str, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let mut limit = match args.limit {
        Some(limit_str) => match limit_str.parse::<usize>() {
            Ok(parsed) => parsed,
            Err(_) => {
                let err_msg = format!("Error: Invalid --limit '{}'", limit_str);
                if let Some(ref json_path) = json_result_path {
                    let envelope = crate::envelope::CliResultEnvelope::new(
                        "powershell-artifacts",
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
        None => crate::POWERSHELL_DEFAULT_LIMIT,
    };

    let history_path = args.history.unwrap_or_else(|| {
        std::env::var("FORENSIC_POWERSHELL_HISTORY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::default_powershell_history_path())
    });

    let script_log_path = args.script_log.unwrap_or_else(|| {
        std::env::var("FORENSIC_POWERSHELL_SCRIPT_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::default_powershell_script_log_path())
    });

    let events_path = args.events.unwrap_or_else(|| {
        std::env::var("FORENSIC_POWERSHELL_EVENTS")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::default_powershell_events_path())
    });

    let transcripts_dir = args.transcripts_dir.unwrap_or_else(|| {
        std::env::var("FORENSIC_POWERSHELL_TRANSCRIPTS")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::default_powershell_transcripts_dir())
    });

    let modules_path = args.modules.unwrap_or_else(|| {
        std::env::var("FORENSIC_POWERSHELL_MODULES")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::default_powershell_modules_path())
    });

    if limit == 0 {
        let err_msg = "Error: --limit must be greater than 0".to_string();
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "powershell-artifacts",
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
    if limit > POWERSHELL_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, POWERSHELL_MAX_LIMIT
        ));
        limit = POWERSHELL_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct PowershellRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let history_shape = detect_powershell_input_shape(&history_path, false);
    let script_log_shape = detect_powershell_input_shape(&script_log_path, false);
    let events_shape = detect_powershell_input_shape(&events_path, false);
    let transcripts_shape = detect_powershell_input_shape(&transcripts_dir, true);
    let modules_shape = detect_powershell_input_shape(&modules_path, false);

    let mut out_rows: Vec<PowershellRow> = Vec::new();
    let mut history_count = 0usize;
    let mut script_log_count = 0usize;
    let mut events_count = 0usize;
    let mut transcripts_count = 0usize;
    let mut modules_count = 0usize;
    let mut deduped_count = 0usize;
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut quality_flags: Vec<String> = Vec::new();

    if history_path.exists() {
        for row in parse_powershell_history_file(&history_path) {
            history_count = history_count.saturating_add(1);
            let executable_name = executable_name_from_command_text(&row.command);
            let output = serde_json::json!({
                "source": "history",
                "event_type": "command-history",
                "timestamp_unix": serde_json::Value::Null,
                "timestamp_utc": serde_json::Value::Null,
                "timestamp_precision": "none",
                "severity": powershell_severity(&row.command),
                "command": row.command,
                "execution_count": row.execution_count,
                "last_used_index": row.last_used,
                "executable_name": executable_name
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(PowershellRow {
                has_ts: false,
                sort_ts: 0,
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!(
            "PowerShell history not found: {}",
            history_path.display()
        ));
    }

    if script_log_path.exists() {
        for row in parse_powershell_script_log_file(&script_log_path) {
            script_log_count = script_log_count.saturating_add(1);
            let ts = if row.timestamp > 0 {
                Some(row.timestamp as i64)
            } else {
                None
            };
            let text = format!("{} {}", row.script_path, row.parameters);
            let executable_name = executable_name_from_command_text(&text)
                .or_else(|| executable_name_from_hint(&row.script_path));
            let output = serde_json::json!({
                "source": "script-log",
                "event_type": "script-log-entry",
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc),
                "timestamp_precision": if ts.is_some() { "seconds" } else { "none" },
                "severity": powershell_severity(&text),
                "script_path": row.script_path,
                "parameters": row.parameters,
                "result": if row.result.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(row.result) },
                "executable_name": executable_name
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(PowershellRow {
                has_ts: ts.is_some(),
                sort_ts: ts.unwrap_or_default(),
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!(
            "PowerShell script log not found: {}",
            script_log_path.display()
        ));
    }

    if events_path.exists() {
        for row in parse_powershell_events_file(&events_path) {
            events_count = events_count.saturating_add(1);
            let ts = if row.timestamp > 0 {
                Some(row.timestamp as i64)
            } else {
                None
            };
            let output = serde_json::json!({
                "source": "event",
                "event_type": "script-block-event",
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc),
                "timestamp_precision": if ts.is_some() { "seconds" } else { "none" },
                "severity": powershell_severity(&row.script),
                "script": row.script,
                "executable_name": executable_name_from_command_text(&row.script)
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(PowershellRow {
                has_ts: ts.is_some(),
                sort_ts: ts.unwrap_or_default(),
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!(
            "PowerShell events not found: {}",
            events_path.display()
        ));
    }

    if transcripts_dir.exists() {
        for row in parse_powershell_transcripts_dir(&transcripts_dir) {
            transcripts_count = transcripts_count.saturating_add(1);
            let ts = if row.start_time > 0 {
                Some(row.start_time as i64)
            } else {
                None
            };
            let output = serde_json::json!({
                "source": "transcript",
                "event_type": "transcript-file",
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc),
                "timestamp_precision": if ts.is_some() { "seconds" } else { "none" },
                "severity": "info",
                "path": row.path,
                "start_time": row.start_time,
                "end_time": row.end_time,
                "command_count": row.command_count
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(PowershellRow {
                has_ts: ts.is_some(),
                sort_ts: ts.unwrap_or_default(),
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!(
            "PowerShell transcripts directory not found: {}",
            transcripts_dir.display()
        ));
    }

    if modules_path.exists() {
        for row in parse_powershell_modules_inventory(&modules_path) {
            modules_count = modules_count.saturating_add(1);
            let output = serde_json::json!({
                "source": "module",
                "event_type": "module-inventory",
                "timestamp_unix": serde_json::Value::Null,
                "timestamp_utc": serde_json::Value::Null,
                "timestamp_precision": "none",
                "severity": "info",
                "name": row.name,
                "version": if row.version.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(row.version) },
                "path": if row.path.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(row.path) },
                "description": if row.description.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(row.description) }
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(PowershellRow {
                has_ts: false,
                sort_ts: 0,
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!(
            "PowerShell modules inventory not found: {}",
            modules_path.display()
        ));
    }

    if history_shape == PowershellInputShape::JsonArray
        || history_shape == PowershellInputShape::JsonObject
    {
        quality_flags.push("history_input_not_line_text".to_string());
    }
    if !matches!(
        script_log_shape,
        PowershellInputShape::PipeDelimited
            | PowershellInputShape::CsvDelimited
            | PowershellInputShape::LineText
            | PowershellInputShape::Missing
            | PowershellInputShape::Empty
    ) {
        quality_flags.push("script_log_input_unexpected_shape".to_string());
    }
    if !matches!(
        events_shape,
        PowershellInputShape::JsonArray
            | PowershellInputShape::JsonObject
            | PowershellInputShape::PipeDelimited
            | PowershellInputShape::CsvDelimited
            | PowershellInputShape::LineText
            | PowershellInputShape::Missing
            | PowershellInputShape::Empty
    ) {
        quality_flags.push("events_input_unexpected_shape".to_string());
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

    let fallback_used = matches!(
        events_shape,
        PowershellInputShape::PipeDelimited
            | PowershellInputShape::CsvDelimited
            | PowershellInputShape::LineText
    ) && events_count > 0;

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
            "history": history_path.to_string_lossy().to_string(),
            "history_found": history_path.exists(),
            "script_log": script_log_path.to_string_lossy().to_string(),
            "script_log_found": script_log_path.exists(),
            "events": events_path.to_string_lossy().to_string(),
            "events_found": events_path.exists(),
            "transcripts_dir": transcripts_dir.to_string_lossy().to_string(),
            "transcripts_found": transcripts_dir.exists(),
            "modules": modules_path.to_string_lossy().to_string(),
            "modules_found": modules_path.exists()
        },
        "source_rows": {
            "history": history_count,
            "script_log": script_log_count,
            "events": events_count,
            "transcripts": transcripts_count,
            "modules": modules_count
        },
        "quality": {
            "input_shapes": {
                "history": history_shape.as_str(),
                "script_log": script_log_shape.as_str(),
                "events": events_shape.as_str(),
                "transcripts": transcripts_shape.as_str(),
                "modules": modules_shape.as_str()
            },
            "parser_mode": "multi-source-merge",
            "fallback_used": fallback_used,
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
        println!("=== PowerShell Artifacts ===");
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        println!(
            "Rows: history={} script_log={} events={} transcripts={} modules={}",
            history_count, script_log_count, events_count, transcripts_count, modules_count
        );
        println!(
            "Quality: deduped={} timestamp_rows={} executable_rows={}",
            deduped_count, timestamp_rows, executable_rows
        );
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "powershell-artifacts",
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

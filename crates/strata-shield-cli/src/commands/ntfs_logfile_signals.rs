// Extracted from main.rs - run_ntfs_logfile_signals_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "ntfs-logfile-signals",
    about = "Parse and normalize NTFS LogFile signals"
)]
pub struct NtfsLogfileSignalsArgs {
    #[arg(long = "logfile-input", alias = "input")]
    pub logfile_input: Option<PathBuf>,

    #[arg(short, long)]
    pub limit: Option<String>,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: NtfsLogfileSignalsArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let input_path = args.logfile_input.unwrap_or_else(|| {
        env::var("FORENSIC_LOGFILE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("exports").join("logfile.bin"))
    });
    let mut limit = NTFS_LOGFILE_SIGNALS_DEFAULT_LIMIT;
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    if let Some(limit_raw) = args.limit {
        match limit_raw.parse::<usize>() {
            Ok(parsed) => {
                limit = parsed;
            }
            Err(_) => {
                let err_msg = format!("Error: Invalid --limit '{}'", limit_raw);
                if let Some(ref json_path) = json_result_path {
                    let envelope = CliResultEnvelope::new(
                        "ntfs-logfile-signals",
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
    }
    if limit == 0 {
        let err_msg = "Error: --limit must be greater than 0".to_string();
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "ntfs-logfile-signals",
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
    if limit > NTFS_LOGFILE_SIGNALS_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, NTFS_LOGFILE_SIGNALS_MAX_LIMIT
        ));
        limit = NTFS_LOGFILE_SIGNALS_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct OutputRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let input_shape =
        forensic_engine::classification::logfile::detect_ntfs_logfile_input_shape(&input_path);
    let mut out_rows: Vec<OutputRow> = Vec::new();
    let mut primary_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    if input_path.exists() {
        match strata_fs::read(&input_path) {
            Ok(raw) => {
                let parsed_primary =
                    forensic_engine::classification::logfile::parse_ntfs_logfile_signals(
                        &raw, limit,
                    );
                primary_rows = parsed_primary.len();
                let rows = if parsed_primary.is_empty() {
                    let parsed_fallback =
                        forensic_engine::classification::logfile::parse_ntfs_logfile_text_fallback(
                            &input_path,
                            limit,
                        );
                    fallback_rows = parsed_fallback.len();
                    if fallback_rows == 0 {
                        warnings.push(format!(
                            "No NTFS LogFile rows parsed from input: {}",
                            input_path.display()
                        ));
                    }
                    parsed_fallback
                } else {
                    parsed_primary
                };

                for row in rows {
                    let timestamp_unix = row.timestamp_unix.or_else(|| {
                        row.timestamp_utc
                            .as_deref()
                            .and_then(parse_utc_to_unix_seconds)
                    });
                    let timestamp_utc = timestamp_unix
                        .map(unix_seconds_to_utc)
                        .or(row.timestamp_utc);
                    let signal_lc = row.signal.to_ascii_lowercase();
                    let process_path = row.process_path.map(|v| v.replace('/', "\\"));
                    let output = serde_json::json!({
                        "offset": row.offset,
                        "signal": row.signal,
                        "event_type": signal_lc.replace('_', "-"),
                        "event_category": if signal_lc.contains("mft") || signal_lc.contains("usn") { "metadata" } else { "filesystem" },
                        "context": row.context,
                        "timestamp_unix": timestamp_unix,
                        "timestamp_utc": timestamp_utc,
                        "timestamp_precision": if timestamp_unix.is_some() { "seconds" } else { "none" },
                        "severity": if signal_lc.contains("delete") || signal_lc.contains("truncate") || signal_lc.contains("rename") { "warn" } else { "info" },
                        "sid": row.sid,
                        "user": row.user,
                        "device": row.device,
                        "process_path": process_path,
                        "executable_name": process_path
                            .as_deref()
                            .and_then(executable_name_from_hint)
                            .or_else(|| executable_name_from_command_text(row.context.as_str()))
                            .or_else(|| executable_name_from_hint(row.context.as_str())),
                        "source_module": row.source_module.unwrap_or_else(|| "ntfs-logfile-signals".to_string()),
                        "dedupe_reason": row.dedupe_reason
                    });
                    let key = format!(
                        "{}|{}|{}|{}|{}",
                        output["offset"].as_u64().unwrap_or_default(),
                        output["signal"].as_str().unwrap_or(""),
                        output["context"].as_str().unwrap_or(""),
                        output["timestamp_unix"]
                            .as_i64()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "null".to_string()),
                        output["process_path"].as_str().unwrap_or("")
                    );
                    if !seen_dedupe.insert(key.clone()) {
                        deduped_count = deduped_count.saturating_add(1);
                        continue;
                    }
                    out_rows.push(OutputRow {
                        has_ts: timestamp_unix.is_some(),
                        sort_ts: timestamp_unix.unwrap_or_default(),
                        tie_key: key,
                        row: output,
                    });
                }
            }
            Err(_) => warnings.push(format!(
                "Could not read NTFS LogFile input: {}",
                input_path.display()
            )),
        }
    } else {
        warnings.push(format!(
            "NTFS LogFile input not found: {}",
            input_path.display()
        ));
    }

    if matches!(
        input_shape,
        forensic_engine::classification::logfile::NtfsLogFileInputShape::Unknown
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
    let process_rows = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("process_path")
                .and_then(|v| v.as_str())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();
    let sid_rows = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("sid")
                .and_then(|v| v.as_str())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();
    let warn_rows = out_rows
        .iter()
        .filter(|row| row.row.get("severity").and_then(|v| v.as_str()) == Some("warn"))
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
            "rows_with_process": process_rows,
            "rows_with_sid": sid_rows,
            "warn_rows": warn_rows,
            "warning_count": warnings.len()
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "ntfs-logfile-normalized-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "offset+signal+context+timestamp+process_path",
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
        println!("=== NTFS LogFile Signals ===");
        println!("Rows: primary={} fallback={}", primary_rows, fallback_rows);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "ntfs-logfile-signals",
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

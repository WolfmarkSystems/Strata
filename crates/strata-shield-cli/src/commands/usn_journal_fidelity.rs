// Extracted from main.rs - run_usn_journal_fidelity_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "usn-journal-fidelity",
    about = "Parse and normalize USN journal fidelity records"
)]
pub struct UsnJournalFidelityArgs {
    #[arg(long = "usn-input", alias = "input")]
    pub usn_input: Option<PathBuf>,

    #[arg(short, long)]
    pub limit: Option<String>,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: UsnJournalFidelityArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let usn_input = args.usn_input.unwrap_or_else(|| {
        env::var("FORENSIC_USN_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("exports").join("usnjrnl.csv"))
    });
    let mut limit = USN_JOURNAL_FIDELITY_DEFAULT_LIMIT;
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
                        "usn-journal-fidelity",
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
                "usn-journal-fidelity",
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
    if limit > USN_JOURNAL_FIDELITY_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, USN_JOURNAL_FIDELITY_MAX_LIMIT
        ));
        limit = USN_JOURNAL_FIDELITY_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct OutputRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let input_shape =
        forensic_engine::classification::usnjrnl::detect_usnjrnl_input_shape(&usn_input);
    let mut out_rows: Vec<OutputRow> = Vec::new();
    let mut primary_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    if usn_input.exists() {
        if let Ok(raw) = strata_fs::read(&usn_input) {
            let parsed_primary =
                forensic_engine::classification::usnjrnl::parse_usnjrnl_records(&raw);
            primary_rows = parsed_primary.len();
            let rows = if parsed_primary.is_empty() {
                let parsed_fallback =
                    forensic_engine::classification::usnjrnl::parse_usnjrnl_text_fallback(
                        &usn_input,
                    );
                fallback_rows = parsed_fallback.len();
                if fallback_rows == 0 {
                    warnings.push(format!(
                        "No USN records parsed from input: {}",
                        usn_input.display()
                    ));
                }
                parsed_fallback
            } else {
                parsed_primary
            };

            for row in rows {
                let path_canonical = row.file_path.as_ref().map(|v| v.replace('/', "\\"));
                let reason_flags = row.reason_flags.clone();
                let event_type = reason_flags
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "USN_CHANGE".to_string());
                let severity = if reason_flags.iter().any(|flag| flag == "FILE_DELETE") {
                    "warn"
                } else {
                    "info"
                };
                let output = serde_json::json!({
                    "usn": row.usn,
                    "file_reference": row.file_reference,
                    "parent_reference": row.parent_reference,
                    "file_name": row.file_name,
                    "file_path": row.file_path,
                    "file_path_canonical": path_canonical,
                    "reason_raw": row.reason_raw,
                    "reason_flags": reason_flags,
                    "event_type": event_type,
                    "severity": severity,
                    "timestamp_unix": row.timestamp_unix,
                    "timestamp_utc": row.timestamp_utc,
                    "timestamp_precision": if row.timestamp_unix.is_some() { "seconds" } else { "none" },
                    "executable_name": path_canonical
                        .as_deref()
                        .and_then(executable_name_from_hint)
                        .or_else(|| row.file_name.as_deref().and_then(executable_name_from_hint))
                });
                let key = format!(
                    "{}|{}|{}|{}|{}",
                    output["usn"].as_u64().unwrap_or_default(),
                    output["file_path_canonical"].as_str().unwrap_or(""),
                    output["timestamp_unix"]
                        .as_i64()
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "null".to_string()),
                    output["event_type"].as_str().unwrap_or(""),
                    output["severity"].as_str().unwrap_or("")
                );
                if !seen_dedupe.insert(key.clone()) {
                    deduped_count = deduped_count.saturating_add(1);
                    continue;
                }
                out_rows.push(OutputRow {
                    has_ts: output
                        .get("timestamp_unix")
                        .and_then(|v| v.as_i64())
                        .is_some(),
                    sort_ts: output
                        .get("timestamp_unix")
                        .and_then(|v| v.as_i64())
                        .unwrap_or_default(),
                    tie_key: key,
                    row: output,
                });
            }
        } else {
            warnings.push(format!("Could not read USN input: {}", usn_input.display()));
        }
    } else {
        warnings.push(format!("USN input not found: {}", usn_input.display()));
    }

    if matches!(
        input_shape,
        forensic_engine::classification::usnjrnl::UsnInputShape::Unknown
            | forensic_engine::classification::usnjrnl::UsnInputShape::Binary
    ) {
        quality_flags.push("input_shape_unexpected_for_usn_parser".to_string());
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
    let rows_with_path = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("file_path_canonical")
                .and_then(|v| v.as_str())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();
    let delete_rows = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("reason_flags")
                .and_then(|v| v.as_array())
                .map(|flags| {
                    flags
                        .iter()
                        .filter_map(|v| v.as_str())
                        .any(|v| v == "FILE_DELETE")
                })
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
        "input_path": usn_input.to_string_lossy().to_string(),
        "input_exists": usn_input.exists(),
        "limit": limit,
        "total_available": total_available,
        "total_returned": records.len(),
        "source_rows": {
            "primary": primary_rows,
            "fallback": fallback_rows
        },
        "summary": {
            "timestamp_rows": timestamp_rows,
            "rows_with_path": rows_with_path,
            "delete_rows": delete_rows,
            "warning_count": warnings.len()
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "usn-normalized-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "usn+path+timestamp+event_type+severity",
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
        println!("=== USN Journal Fidelity ===");
        println!("Rows: primary={} fallback={}", primary_rows, fallback_rows);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "usn-journal-fidelity",
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

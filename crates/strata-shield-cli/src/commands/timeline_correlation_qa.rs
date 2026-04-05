// Extracted from main.rs — run_timeline_correlation_qa_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "timeline-correlation-qa",
    about = "Parse and normalize timeline-correlation QA records"
)]
pub struct TimelineCorrelationQaArgs {
    #[arg(long = "input", alias = "timeline-input", alias = "qa-input")]
    pub input: Option<PathBuf>,

    #[arg(short, long)]
    pub limit: Option<String>,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: TimelineCorrelationQaArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let input_path = args.input.unwrap_or_else(|| {
        env::var("FORENSIC_TIMELINE_CORRELATION_QA_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("exports").join("timeline_correlation_qa.json"))
    });
    let mut limit = TIMELINE_CORRELATION_QA_DEFAULT_LIMIT;
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
                        "timeline-correlation-qa",
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
                "timeline-correlation-qa",
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
    if limit > TIMELINE_CORRELATION_QA_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, TIMELINE_CORRELATION_QA_MAX_LIMIT
        ));
        limit = TIMELINE_CORRELATION_QA_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct OutputRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let input_shape = forensic_engine::classification::timeline_correlation_qa::detect_timeline_correlation_input_shape(&input_path);
    let mut out_rows: Vec<OutputRow> = Vec::new();
    let mut primary_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    if input_path.exists() {
        let parsed_primary = parse_timeline_correlation_qa_records_from_path(&input_path, limit);
        primary_rows = parsed_primary.len();
        let rows = if parsed_primary.is_empty() && input_path.is_file() {
            let parsed_fallback =
                forensic_engine::classification::timeline_correlation_qa::parse_timeline_correlation_qa_text_fallback(&input_path);
            fallback_rows = parsed_fallback.len();
            if fallback_rows == 0 {
                warnings.push(format!(
                    "No timeline-correlation QA rows parsed from input: {}",
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
                "event_category": row.event_category,
                "summary": row.summary,
                "severity": row.severity,
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc).or(row.timestamp_utc),
                "timestamp_precision": row.timestamp_precision,
                "executable_name": row.executable_name,
                "command": row.command,
                "path": row.path,
                "source_module": row.source_module.or_else(|| Some("timeline-correlation-qa".to_string())),
                "source_record_id": row.source_record_id,
                "case_id": row.case_id,
                "evidence_id": row.evidence_id,
                "actor": row.actor,
                "data_json": row.data_json
            });
            let key = format!(
                "{}|{}|{}|{}|{}",
                output["source"].as_str().unwrap_or(""),
                output["event_type"].as_str().unwrap_or(""),
                output["timestamp_unix"]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                output["executable_name"].as_str().unwrap_or(""),
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
            "Timeline-correlation QA input not found: {}",
            input_path.display()
        ));
    }

    if matches!(
        input_shape,
        forensic_engine::classification::timeline_correlation_qa::TimelineCorrelationInputShape::Unknown
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
    let warn_or_error_rows = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("severity")
                .and_then(|v| v.as_str())
                .map(|v| v == "warn" || v == "error")
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
            "warn_or_error_rows": warn_or_error_rows,
            "warning_count": warnings.len()
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "timeline-correlation-qa-normalized-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "source+event_type+timestamp+executable+record",
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
        println!("=== Timeline Correlation QA ===");
        println!("Rows: primary={} fallback={}", primary_rows, fallback_rows);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "timeline-correlation-qa",
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

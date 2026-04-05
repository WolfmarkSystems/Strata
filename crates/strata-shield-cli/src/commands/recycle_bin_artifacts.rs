// Extracted from main.rs - run_recycle_bin_artifacts_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "recycle-bin-artifacts",
    about = "Parse and normalize Recycle Bin artifact records"
)]
pub struct RecycleBinArtifactsArgs {
    #[arg(long = "recycle-input", alias = "input")]
    pub recycle_input: Option<PathBuf>,

    #[arg(short, long)]
    pub limit: Option<String>,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: RecycleBinArtifactsArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let input_path = args.recycle_input.unwrap_or_else(|| {
        env::var("FORENSIC_RECYCLE_BIN_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("exports").join("recycle_bin.json"))
    });
    let mut limit = RECYCLE_BIN_ARTIFACTS_DEFAULT_LIMIT;
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
                        "recycle-bin-artifacts",
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
                "recycle-bin-artifacts",
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
    if limit > RECYCLE_BIN_ARTIFACTS_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, RECYCLE_BIN_ARTIFACTS_MAX_LIMIT
        ));
        limit = RECYCLE_BIN_ARTIFACTS_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct OutputRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let input_shape =
        forensic_engine::classification::recyclebin::detect_recycle_input_shape(&input_path);
    let mut out_rows: Vec<OutputRow> = Vec::new();
    let mut primary_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    if input_path.exists() {
        let parsed_primary =
            forensic_engine::classification::recyclebin::parse_recycle_entries_from_path(
                &input_path,
                limit,
            );
        primary_rows = parsed_primary.len();
        let rows = if parsed_primary.is_empty() {
            let parsed_fallback =
                forensic_engine::classification::recyclebin::parse_recycle_text_fallback(
                    &input_path,
                );
            fallback_rows = parsed_fallback.len();
            if fallback_rows == 0 {
                warnings.push(format!(
                    "No Recycle Bin rows parsed from input: {}",
                    input_path.display()
                ));
            }
            parsed_fallback
        } else {
            parsed_primary
        };

        for row in rows {
            let timestamp_unix = row.deleted_time;
            let timestamp_utc = timestamp_unix.map(unix_seconds_to_utc);
            let original_path = row.original_path.map(|v| v.replace('/', "\\"));
            let output = serde_json::json!({
                "drive_letter": row.drive_letter.to_string(),
                "file_name": row.file_name,
                "original_path": original_path,
                "file_size": row.file_size,
                "deleted_unix": timestamp_unix,
                "deleted_utc": timestamp_utc,
                "timestamp_unix": timestamp_unix,
                "timestamp_utc": timestamp_utc,
                "timestamp_precision": if timestamp_unix.is_some() { "seconds" } else { "none" },
                "event_type": "recycle-delete",
                "event_category": "deletion",
                "severity": "warn",
                "owner_sid": row.owner_sid,
                "user": serde_json::Value::Null,
                "device": row.drive_letter.to_string(),
                "process_path": original_path,
                "executable_name": original_path
                    .as_deref()
                    .and_then(executable_name_from_hint)
                    .or_else(|| executable_name_from_hint(row.file_name.as_str()))
            });
            let key = format!(
                "{}|{}|{}|{}|{}",
                output["original_path"].as_str().unwrap_or(""),
                output["deleted_unix"]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                output["file_size"].as_u64().unwrap_or_default(),
                output["file_name"].as_str().unwrap_or(""),
                output["owner_sid"].as_str().unwrap_or("")
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
    } else {
        warnings.push(format!(
            "Recycle Bin input not found: {}",
            input_path.display()
        ));
    }

    if matches!(
        input_shape,
        forensic_engine::classification::recyclebin::RecycleBinInputShape::Unknown
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
    let sid_rows = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("owner_sid")
                .and_then(|v| v.as_str())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();
    let total_size: u64 = out_rows
        .iter()
        .map(|row| {
            row.row
                .get("file_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        })
        .sum();
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
            "rows_with_owner_sid": sid_rows,
            "total_size_bytes": total_size,
            "warning_count": warnings.len()
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "recycle-bin-normalized-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "path+deleted_unix+size+name+sid",
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
        println!("=== Recycle Bin Artifacts ===");
        println!("Rows: primary={} fallback={}", primary_rows, fallback_rows);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "recycle-bin-artifacts",
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

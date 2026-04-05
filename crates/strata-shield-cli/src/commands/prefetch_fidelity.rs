// Extracted from main.rs - run_prefetch_fidelity_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "prefetch-fidelity",
    about = "Parse and normalize Prefetch fidelity records"
)]
pub struct PrefetchFidelityArgs {
    #[arg(long = "prefetch-input", aliases = ["input", "prefetch-dir"])]
    pub prefetch_input: Option<PathBuf>,

    #[arg(short, long)]
    pub limit: Option<String>,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: PrefetchFidelityArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let input_path = args.prefetch_input.unwrap_or_else(|| {
        env::var("FORENSIC_PREFETCH_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("C:\\Windows\\Prefetch"))
    });
    let mut limit = PREFETCH_FIDELITY_DEFAULT_LIMIT;
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
                        "prefetch-fidelity",
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
                "prefetch-fidelity",
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
    if limit > PREFETCH_FIDELITY_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, PREFETCH_FIDELITY_MAX_LIMIT
        ));
        limit = PREFETCH_FIDELITY_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct OutputRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let input_shape =
        forensic_engine::classification::prefetch::detect_prefetch_input_shape(&input_path);
    let mut out_rows: Vec<OutputRow> = Vec::new();
    let mut primary_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    if input_path.exists() {
        let parsed_primary =
            forensic_engine::classification::prefetch::parse_prefetch_records_from_path(
                &input_path,
                limit,
            );
        primary_rows = parsed_primary.len();
        let rows = if parsed_primary.is_empty() && input_path.is_file() {
            let parsed_fallback =
                forensic_engine::classification::prefetch::parse_prefetch_text_fallback(
                    &input_path,
                );
            fallback_rows = parsed_fallback.len();
            if fallback_rows == 0 {
                warnings.push(format!(
                    "No Prefetch rows parsed from input: {}",
                    input_path.display()
                ));
            }
            parsed_fallback
        } else {
            parsed_primary
        };

        for row in rows {
            let process_path = row
                .files_referenced
                .iter()
                .find(|p| executable_name_from_hint(p).is_some())
                .cloned();
            let output = serde_json::json!({
                "version": row.version,
                "program_name": row.program_name,
                "last_run_unix": row.last_run_time,
                "last_run_utc": row.last_run_time.map(unix_seconds_to_utc),
                "timestamp_unix": row.last_run_time,
                "timestamp_utc": row.last_run_time.map(unix_seconds_to_utc),
                "timestamp_precision": if row.last_run_time.is_some() { "seconds" } else { "none" },
                "run_count": row.run_count,
                "run_times_unix": row.run_times,
                "run_times_utc": row.run_times.iter().map(|v| unix_seconds_to_utc(*v)).collect::<Vec<_>>(),
                "volumes_referenced": row.volumes_referenced,
                "files_referenced": row.files_referenced,
                "directories_referenced": row.directories_referenced,
                "device": row.volumes_referenced.first().cloned(),
                "process_path": process_path,
                "executable_name": executable_name_from_hint(row.program_name.as_str())
                    .or_else(|| process_path.as_deref().and_then(executable_name_from_hint))
            });
            let key = format!(
                "{}|{}|{}|{}",
                output["program_name"].as_str().unwrap_or(""),
                output["last_run_unix"]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                output["run_count"].as_u64().unwrap_or_default(),
                output["process_path"].as_str().unwrap_or("")
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
            "Prefetch input not found: {}",
            input_path.display()
        ));
    }

    if matches!(
        input_shape,
        forensic_engine::classification::prefetch::PrefetchInputShape::Unknown
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
    let rows_with_files = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("files_referenced")
                .and_then(|v| v.as_array())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();
    let rows_with_directories = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("directories_referenced")
                .and_then(|v| v.as_array())
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
            "rows_with_files": rows_with_files,
            "rows_with_directories": rows_with_directories,
            "warning_count": warnings.len()
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "prefetch-fidelity-normalized-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "program+last_run+run_count+process_path",
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
        println!("=== Prefetch Fidelity ===");
        println!("Rows: primary={} fallback={}", primary_rows, fallback_rows);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "prefetch-fidelity",
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

// Extracted from main.rs - run_ntfs_mft_fidelity_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "ntfs-mft-fidelity",
    about = "Parse and normalize NTFS MFT fidelity records"
)]
pub struct NtfsMftFidelityArgs {
    #[arg(long = "mft-input", alias = "input")]
    pub mft_input: Option<PathBuf>,

    #[arg(short, long)]
    pub limit: Option<String>,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: NtfsMftFidelityArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let mft_input = args.mft_input.unwrap_or_else(|| {
        env::var("FORENSIC_MFT_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("exports").join("mft.json"))
    });
    let mut limit = NTFS_MFT_FIDELITY_DEFAULT_LIMIT;
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
                        "ntfs-mft-fidelity",
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
                "ntfs-mft-fidelity",
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
    if limit > NTFS_MFT_FIDELITY_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, NTFS_MFT_FIDELITY_MAX_LIMIT
        ));
        limit = NTFS_MFT_FIDELITY_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct OutputRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let input_shape = forensic_engine::classification::mftparse::detect_mft_input_shape(&mft_input);
    let mut out_rows: Vec<OutputRow> = Vec::new();
    let mut primary_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    let max_scan = std::cmp::max(limit, 1).min(NTFS_MFT_FIDELITY_MAX_LIMIT);
    let mut parsed_rows = forensic_engine::classification::mftparse::parse_mft_records_from_path(
        &mft_input, max_scan,
    );
    if mft_input.exists() {
        primary_rows = parsed_rows.len();
        if parsed_rows.is_empty() {
            parsed_rows =
                forensic_engine::classification::mftparse::parse_mft_text_fallback(&mft_input);
            fallback_rows = parsed_rows.len();
            if fallback_rows == 0 {
                warnings.push(format!(
                    "No MFT records parsed from input: {}",
                    mft_input.display()
                ));
            }
        }
    } else {
        warnings.push(format!("MFT input not found: {}", mft_input.display()));
    }

    let paths = forensic_engine::classification::mftparse::reconstruct_mft_paths(&parsed_rows)
        .into_iter()
        .map(|v| (v.record_number, v.path))
        .collect::<std::collections::BTreeMap<u64, String>>();

    for row in parsed_rows {
        let timestamp_unix = row
            .modified_time
            .or(row.created_time)
            .or(row.mft_modified_time)
            .or(row.accessed_time);
        let timestamp_utc = timestamp_unix.map(unix_seconds_to_utc);
        let full_path = paths
            .get(&row.record_number)
            .filter(|v| !v.trim().is_empty())
            .map(|v| v.replace('/', "\\"));
        let file_name = row.file_name.clone();
        let executable_name = full_path
            .as_deref()
            .and_then(executable_name_from_hint)
            .or_else(|| file_name.as_deref().and_then(executable_name_from_hint));
        let output = serde_json::json!({
            "record_number": row.record_number,
            "sequence_number": row.sequence_number,
            "in_use": row.in_use,
            "deleted": row.deleted,
            "is_directory": row.is_directory,
            "hard_link_count": row.hard_link_count,
            "file_name": file_name,
            "short_name": row.short_name,
            "parent_record_number": row.parent_record_number,
            "full_path": full_path,
            "timestamp_unix": timestamp_unix,
            "timestamp_utc": timestamp_utc,
            "timestamp_precision": if timestamp_unix.is_some() { "seconds" } else { "none" },
            "created_unix": row.created_time,
            "created_utc": row.created_time.map(unix_seconds_to_utc),
            "modified_unix": row.modified_time,
            "modified_utc": row.modified_time.map(unix_seconds_to_utc),
            "mft_modified_unix": row.mft_modified_time,
            "mft_modified_utc": row.mft_modified_time.map(unix_seconds_to_utc),
            "accessed_unix": row.accessed_time,
            "accessed_utc": row.accessed_time.map(unix_seconds_to_utc),
            "executable_name": executable_name
        });
        let key = format!(
            "{}|{}|{}|{}|{}",
            row.record_number,
            row.sequence_number,
            output["full_path"].as_str().unwrap_or(""),
            output["timestamp_unix"]
                .as_i64()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "null".to_string()),
            row.deleted
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

    if matches!(
        input_shape,
        forensic_engine::classification::mftparse::MftInputShape::Unknown
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
    let path_rows = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("full_path")
                .and_then(|v| v.as_str())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();
    let deleted_rows = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("deleted")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .count();
    let directory_rows = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("is_directory")
                .and_then(|v| v.as_bool())
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
        "input_path": mft_input.to_string_lossy().to_string(),
        "input_exists": mft_input.exists(),
        "limit": limit,
        "total_available": total_available,
        "total_returned": records.len(),
        "source_rows": {
            "primary": primary_rows,
            "fallback": fallback_rows
        },
        "summary": {
            "timestamp_rows": timestamp_rows,
            "path_rows": path_rows,
            "deleted_rows": deleted_rows,
            "directory_rows": directory_rows,
            "warning_count": warnings.len()
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "mft-normalized-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "record_number+sequence+path+timestamp+deleted",
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
        println!("=== NTFS MFT Fidelity ===");
        println!("Rows: primary={} fallback={}", primary_rows, fallback_rows);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "ntfs-mft-fidelity",
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

// Extracted from main.rs - run_lnk_shortcut_fidelity_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "lnk-shortcut-fidelity",
    about = "Parse and normalize LNK shortcut fidelity records"
)]
pub struct LnkShortcutFidelityArgs {
    #[arg(long = "lnk-input", aliases = ["input", "shortcuts-base"])]
    pub lnk_input: Option<PathBuf>,

    #[arg(short, long)]
    pub limit: Option<String>,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: LnkShortcutFidelityArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let input_path = args.lnk_input.unwrap_or_else(|| {
        env::var("FORENSIC_LNK_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("exports").join("shortcuts.json"))
    });
    let mut limit = LNK_SHORTCUT_FIDELITY_DEFAULT_LIMIT;
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
                        "lnk-shortcut-fidelity",
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
                "lnk-shortcut-fidelity",
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
    if limit > LNK_SHORTCUT_FIDELITY_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, LNK_SHORTCUT_FIDELITY_MAX_LIMIT
        ));
        limit = LNK_SHORTCUT_FIDELITY_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct OutputRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let input_shape = forensic_engine::classification::lnk::detect_lnk_input_shape(&input_path);
    let mut out_rows: Vec<OutputRow> = Vec::new();
    let mut primary_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    if input_path.exists() {
        let parsed_primary = parse_lnk_shortcuts_from_path(&input_path, limit);
        primary_rows = parsed_primary.len();
        let rows = if parsed_primary.is_empty() && input_path.is_file() {
            let parsed_fallback =
                forensic_engine::classification::lnk::parse_lnk_text_fallback(&input_path);
            fallback_rows = parsed_fallback.len();
            if fallback_rows == 0 {
                warnings.push(format!(
                    "No LNK rows parsed from input: {}",
                    input_path.display()
                ));
            }
            parsed_fallback
        } else {
            parsed_primary
        };

        for row in rows {
            let ts = row
                .write_time_unix
                .or(row.modified_unix)
                .or(row.created_unix);
            let output = serde_json::json!({
                "path": row.path,
                "target_path": row.target_path,
                "arguments": row.arguments,
                "working_directory": row.working_directory,
                "description": row.description,
                "created_unix": row.created_unix,
                "modified_unix": row.modified_unix,
                "access_time_unix": row.access_time_unix,
                "write_time_unix": row.write_time_unix,
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc),
                "timestamp_precision": if ts.is_some() { "seconds" } else { "none" },
                "drive_type": row.drive_type,
                "drive_serial": row.drive_serial,
                "machine_id": row.machine_id,
                "event_type": "lnk-shortcut",
                "event_category": "execution",
                "severity": "info",
                "source_module": "lnk-shortcut-fidelity",
                "executable_name": row
                    .target_path
                    .as_deref()
                    .and_then(executable_name_from_hint)
                    .or_else(|| row.arguments.as_deref().and_then(executable_name_from_command_text))
            });
            let key = format!(
                "{}|{}|{}|{}",
                output["path"].as_str().unwrap_or(""),
                output["target_path"].as_str().unwrap_or(""),
                output["timestamp_unix"]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                output["arguments"].as_str().unwrap_or("")
            );
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(OutputRow {
                has_ts: ts.is_some(),
                sort_ts: ts.unwrap_or_default(),
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!("LNK input not found: {}", input_path.display()));
    }

    if matches!(
        input_shape,
        forensic_engine::classification::lnk::LnkInputShape::Unknown
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
    let rows_with_target = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("target_path")
                .and_then(|v| v.as_str())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();
    let rows_with_arguments = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("arguments")
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
            "rows_with_target": rows_with_target,
            "rows_with_arguments": rows_with_arguments,
            "warning_count": warnings.len()
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "lnk-shortcut-fidelity-normalized-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "path+target+timestamp+arguments",
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
        println!("=== LNK Shortcut Fidelity ===");
        println!("Rows: primary={} fallback={}", primary_rows, fallback_rows);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "lnk-shortcut-fidelity",
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

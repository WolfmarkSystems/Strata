// Extracted from main.rs - run_usb_device_history_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "usb-device-history",
    about = "Parse and normalize USB device history records"
)]
pub struct UsbDeviceHistoryArgs {
    #[arg(long = "usb-input", alias = "input")]
    pub usb_input: Option<PathBuf>,

    #[arg(short, long)]
    pub limit: Option<String>,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: UsbDeviceHistoryArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let input_path = args.usb_input.unwrap_or_else(|| {
        env::var("FORENSIC_USB_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("exports").join("usb.json"))
    });
    let mut limit = USB_DEVICE_HISTORY_DEFAULT_LIMIT;
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
                        "usb-device-history",
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
                "usb-device-history",
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
    if limit > USB_DEVICE_HISTORY_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, USB_DEVICE_HISTORY_MAX_LIMIT
        ));
        limit = USB_DEVICE_HISTORY_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct OutputRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let input_shape = forensic_engine::classification::usb::detect_usb_input_shape(&input_path);
    let mut out_rows: Vec<OutputRow> = Vec::new();
    let mut primary_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    if input_path.exists() {
        let parsed_primary = parse_usb_records_from_path(&input_path, limit);
        primary_rows = parsed_primary.len();
        let rows = if parsed_primary.is_empty() && input_path.is_file() {
            let parsed_fallback =
                forensic_engine::classification::usb::parse_usb_text_fallback(&input_path);
            fallback_rows = parsed_fallback.len();
            if fallback_rows == 0 {
                warnings.push(format!(
                    "No USB rows parsed from input: {}",
                    input_path.display()
                ));
            }
            parsed_fallback
        } else {
            parsed_primary
        };

        for row in rows {
            let ts = row
                .timestamp_unix
                .or(row.last_connected_unix)
                .or(row.first_install_unix);
            let vendor_name = row
                .vendor_id
                .as_deref()
                .map(forensic_engine::classification::get_usb_vendor_name);
            let output = serde_json::json!({
                "vendor_id": row.vendor_id,
                "vendor_name": vendor_name,
                "product_id": row.product_id,
                "serial_number": row.serial_number,
                "friendly_name": row.friendly_name,
                "first_install_unix": row.first_install_unix,
                "last_connected_unix": row.last_connected_unix,
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc),
                "timestamp_precision": row.timestamp_precision,
                "user_sid": row.user_sid,
                "username": row.username,
                "device_instance_id": row.device_instance_id,
                "device_class": row.device_class,
                "source_path": row.source_path,
                "source_record_id": row.source_record_id,
                "event_type": "usb-device",
                "event_category": "device-history",
                "severity": "info",
                "source_module": "usb-device-history"
            });
            let key = format!(
                "{}|{}|{}|{}|{}",
                output["vendor_id"].as_str().unwrap_or(""),
                output["product_id"].as_str().unwrap_or(""),
                output["serial_number"].as_str().unwrap_or(""),
                output["timestamp_unix"]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                output["device_instance_id"].as_str().unwrap_or("")
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
        warnings.push(format!("USB input not found: {}", input_path.display()));
    }

    if matches!(
        input_shape,
        forensic_engine::classification::usb::UsbInputShape::Unknown
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
    let rows_with_serial = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("serial_number")
                .and_then(|v| v.as_str())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();
    let rows_with_friendly_name = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("friendly_name")
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
            "rows_with_serial": rows_with_serial,
            "rows_with_friendly_name": rows_with_friendly_name,
            "warning_count": warnings.len()
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "usb-device-history-normalized-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "vendor+product+serial+timestamp+instance",
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
        println!("=== USB Device History ===");
        println!("Rows: primary={} fallback={}", primary_rows, fallback_rows);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "usb-device-history",
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

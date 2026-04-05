// Extracted from main.rs — run_wmi_persistence_activity_command
// TODO: Convert to clap derive args in a future pass

use crate::*;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "wmi-persistence-activity",
    about = "Extract forensic data from WMI Persistence, Traces, and Instances"
)]
pub struct WmiArgs {
    #[arg(long, help = "WMI persistence JSON path")]
    pub persist_input: Option<PathBuf>,

    #[arg(long, help = "WMI traces JSON path")]
    pub traces_input: Option<PathBuf>,

    #[arg(long, help = "WMI instances JSON path")]
    pub instances_input: Option<PathBuf>,

    #[arg(short, long, help = "Limit records (default: 200, max: 5000)")]
    pub limit: Option<String>,

    #[arg(short, long, help = "Print command payload as JSON")]
    pub json: bool,

    #[arg(long, help = "Write envelope JSON to file")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long, help = "Suppress console summary output")]
    pub quiet: bool,
}

pub fn execute(args: WmiArgs, _command_name: &str, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let persist_input = args.persist_input.unwrap_or_else(|| {
        PathBuf::from("artifacts")
            .join("wmi")
            .join("persistence.json")
    });
    let traces_input = args
        .traces_input
        .unwrap_or_else(|| PathBuf::from("artifacts").join("wmi").join("traces.json"));
    let instances_input = args.instances_input.unwrap_or_else(|| {
        PathBuf::from("artifacts")
            .join("wmi")
            .join("instances.json")
    });

    let mut limit = match args.limit {
        Some(limit_str) => match limit_str.parse::<usize>() {
            Ok(parsed) => parsed,
            Err(_) => {
                let err_msg = format!("Error: Invalid --limit '{}'", limit_str);
                if let Some(ref json_path) = json_result_path {
                    let envelope = crate::envelope::CliResultEnvelope::new(
                        "wmi-persistence-activity",
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
        None => crate::WMI_PERSISTENCE_DEFAULT_LIMIT,
    };

    if limit == 0 {
        let err_msg = "Error: --limit must be greater than 0".to_string();
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "wmi-persistence-activity",
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
    if limit > WMI_PERSISTENCE_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, WMI_PERSISTENCE_MAX_LIMIT
        ));
        limit = WMI_PERSISTENCE_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct WmiRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let persist_shape =
        forensic_engine::classification::wmi::detect_wmi_input_shape(&persist_input);
    let traces_shape = forensic_engine::classification::wmi::detect_wmi_input_shape(&traces_input);
    let instances_shape =
        forensic_engine::classification::wmi::detect_wmi_input_shape(&instances_input);

    let mut out_rows: Vec<WmiRow> = Vec::new();
    let mut persistence_rows = 0usize;
    let mut traces_rows = 0usize;
    let mut instances_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    if persist_input.exists() {
        for row in forensic_engine::classification::wmipersist::get_wmi_persistence_from_path(
            &persist_input,
        ) {
            persistence_rows = persistence_rows.saturating_add(1);
            let consumer = row.consumer;
            let filter = row.filter;
            let output = serde_json::json!({
                "source": "persistence",
                "event_type": "wmi-persistence-binding",
                "timestamp_unix": serde_json::Value::Null,
                "timestamp_utc": serde_json::Value::Null,
                "timestamp_precision": "none",
                "severity": "warn",
                "consumer": if consumer.trim().is_empty() { serde_json::Value::Null } else { serde_json::Value::String(consumer.clone()) },
                "consumer_canonical": consumer.to_ascii_lowercase(),
                "filter": if filter.trim().is_empty() { serde_json::Value::Null } else { serde_json::Value::String(filter.clone()) },
                "filter_canonical": filter.to_ascii_lowercase(),
                "executable_name": executable_name_from_command_text(&format!("{} {}", consumer, filter))
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(WmiRow {
                has_ts: false,
                sort_ts: 0,
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!(
            "WMI persistence input not found: {}",
            persist_input.display()
        ));
    }

    if traces_input.exists() {
        for row in
            forensic_engine::classification::wmitrace::get_wmi_traces_from_path(&traces_input)
        {
            traces_rows = traces_rows.saturating_add(1);
            let ts = if row.timestamp > 0 {
                Some(row.timestamp as i64)
            } else {
                None
            };
            let namespace = row.namespace;
            let output = serde_json::json!({
                "source": "trace",
                "event_type": "wmi-trace",
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc),
                "timestamp_precision": if ts.is_some() { "seconds" } else { "none" },
                "severity": "info",
                "namespace": if namespace.trim().is_empty() { serde_json::Value::Null } else { serde_json::Value::String(namespace.clone()) },
                "namespace_canonical": namespace.to_ascii_lowercase()
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(WmiRow {
                has_ts: ts.is_some(),
                sort_ts: ts.unwrap_or_default(),
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!(
            "WMI traces input not found: {}",
            traces_input.display()
        ));
    }

    if instances_input.exists() {
        for row in forensic_engine::classification::wmiinst::get_wmi_class_instances_from_path(
            &instances_input,
        ) {
            instances_rows = instances_rows.saturating_add(1);
            let mut property_pairs = row.properties;
            property_pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let output = serde_json::json!({
                "source": "instance",
                "event_type": "wmi-class-instance",
                "timestamp_unix": serde_json::Value::Null,
                "timestamp_utc": serde_json::Value::Null,
                "timestamp_precision": "none",
                "severity": "info",
                "class_name": row.class,
                "class_name_canonical": row.class.to_ascii_lowercase(),
                "property_count": property_pairs.len(),
                "properties": property_pairs
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(WmiRow {
                has_ts: false,
                sort_ts: 0,
                tie_key: key,
                row: output,
            });
        }
    } else {
        warnings.push(format!(
            "WMI instances input not found: {}",
            instances_input.display()
        ));
    }

    if out_rows.is_empty() {
        for path in [&persist_input, &traces_input, &instances_input] {
            for row in parse_registry_text_fallback(path, "wmi-text") {
                fallback_rows = fallback_rows.saturating_add(1);
                let key = powershell_record_dedupe_key(&row);
                if !seen_dedupe.insert(key.clone()) {
                    deduped_count = deduped_count.saturating_add(1);
                    continue;
                }
                out_rows.push(WmiRow {
                    has_ts: false,
                    sort_ts: 0,
                    tie_key: key,
                    row,
                });
            }
        }
    }

    if matches!(
        persist_shape,
        forensic_engine::classification::wmi::WmiInputShape::Unknown
            | forensic_engine::classification::wmi::WmiInputShape::Binary
    ) || matches!(
        traces_shape,
        forensic_engine::classification::wmi::WmiInputShape::Unknown
            | forensic_engine::classification::wmi::WmiInputShape::Binary
    ) || matches!(
        instances_shape,
        forensic_engine::classification::wmi::WmiInputShape::Unknown
            | forensic_engine::classification::wmi::WmiInputShape::Binary
    ) {
        quality_flags.push("one_or_more_inputs_have_unexpected_shape".to_string());
    }
    if persist_input.exists() && persistence_rows == 0 {
        warnings.push(format!(
            "WMI persistence input was readable but produced no rows: {}",
            persist_input.display()
        ));
    }
    if traces_input.exists() && traces_rows == 0 {
        warnings.push(format!(
            "WMI traces input was readable but produced no rows: {}",
            traces_input.display()
        ));
    }
    if instances_input.exists() && instances_rows == 0 {
        warnings.push(format!(
            "WMI instances input was readable but produced no rows: {}",
            instances_input.display()
        ));
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
            "persist_input": persist_input.to_string_lossy().to_string(),
            "persist_found": persist_input.exists(),
            "traces_input": traces_input.to_string_lossy().to_string(),
            "traces_found": traces_input.exists(),
            "instances_input": instances_input.to_string_lossy().to_string(),
            "instances_found": instances_input.exists()
        },
        "source_rows": {
            "persistence": persistence_rows,
            "traces": traces_rows,
            "instances": instances_rows
        },
        "summary": {
            "timestamp_rows": timestamp_rows,
            "rows_with_executable": rows_with_executable,
            "warning_count": warnings.len()
        },
        "quality": {
            "input_shapes": {
                "persistence": persist_shape.as_str(),
                "traces": traces_shape.as_str(),
                "instances": instances_shape.as_str(),
            },
            "parser_mode": "multi-source-wmi-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "source+timestamp+core_fields",
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
        println!("=== WMI Persistence and Activity ===");
        println!(
            "Rows: persistence={} traces={} instances={}",
            persistence_rows, traces_rows, instances_rows
        );
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "wmi-persistence-activity",
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

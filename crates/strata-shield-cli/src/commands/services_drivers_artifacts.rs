// Extracted from main.rs — run_services_drivers_artifacts_command
// TODO: Convert to clap derive args in a future pass

use crate::*;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "services-drivers-artifacts",
    about = "Extract forensic data from Services and Drivers"
)]
pub struct ServicesDriversArgs {
    #[arg(
        long,
        visible_alias = "input",
        help = "Services/Drivers .reg export path"
    )]
    pub services_reg: Option<PathBuf>,

    #[arg(short, long, help = "Limit records (default: 200, max: 5000)")]
    pub limit: Option<String>,

    #[arg(short, long, help = "Print command payload as JSON")]
    pub json: bool,

    #[arg(long, help = "Write envelope JSON to file")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long, help = "Suppress console summary output")]
    pub quiet: bool,
}

pub fn execute(args: ServicesDriversArgs, _command_name: &str, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let services_reg_path = args
        .services_reg
        .unwrap_or_else(|| PathBuf::from("exports").join("services.reg"));

    let mut limit = match args.limit {
        Some(limit_str) => match limit_str.parse::<usize>() {
            Ok(parsed) => parsed,
            Err(_) => {
                let err_msg = format!("Error: Invalid --limit '{}'", limit_str);
                if let Some(ref json_path) = json_result_path {
                    let envelope = crate::envelope::CliResultEnvelope::new(
                        "services-drivers-artifacts",
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
        None => crate::SERVICES_DRIVERS_DEFAULT_LIMIT,
    };

    if limit == 0 {
        let err_msg = "Error: --limit must be greater than 0".to_string();
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "services-drivers-artifacts",
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
    if limit > SERVICES_DRIVERS_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, SERVICES_DRIVERS_MAX_LIMIT
        ));
        limit = SERVICES_DRIVERS_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct ServiceDriverRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let input_shape =
        forensic_engine::classification::regservice::detect_services_drivers_input_shape(
            &services_reg_path,
        );
    let mut out_rows: Vec<ServiceDriverRow> = Vec::new();
    let mut config_rows = 0usize;
    let mut failure_rows = 0usize;
    let mut delayed_rows = 0usize;
    let mut service_dll_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    let normalize_path = |value: &str| value.trim().trim_matches('"').replace('/', "\\");

    if services_reg_path.exists() {
        for row in forensic_engine::classification::regservice::get_services_config_from_reg(
            &services_reg_path,
        ) {
            config_rows = config_rows.saturating_add(1);
            let image_path = normalize_path(&row.path);
            let output = serde_json::json!({
                "source": "service-config",
                "event_type": "service-config",
                "timestamp_unix": serde_json::Value::Null,
                "timestamp_utc": serde_json::Value::Null,
                "timestamp_precision": "none",
                "severity": "info",
                "service_name": row.name,
                "service_name_canonical": row.name.to_ascii_lowercase(),
                "display_name": if row.display_name.trim().is_empty() { serde_json::Value::Null } else { serde_json::Value::String(row.display_name) },
                "start_type": row.start_type,
                "service_type": row.service_type,
                "service_account": row.service_account,
                "image_path": if image_path.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(image_path.clone()) },
                "description": row.description,
                "executable_name": executable_name_from_hint(&image_path)
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(ServiceDriverRow {
                has_ts: false,
                sort_ts: 0,
                tie_key: key,
                row: output,
            });
        }

        for row in forensic_engine::classification::regservice::get_service_failure_from_reg(
            &services_reg_path,
        ) {
            failure_rows = failure_rows.saturating_add(1);
            let output = serde_json::json!({
                "source": "service-failure",
                "event_type": "service-failure-policy",
                "timestamp_unix": serde_json::Value::Null,
                "timestamp_utc": serde_json::Value::Null,
                "timestamp_precision": "none",
                "severity": "warn",
                "service_name": row.service,
                "service_name_canonical": row.service.to_ascii_lowercase(),
                "reset_period": row.reset_period,
                "actions_count": row.actions.len(),
                "actions": row.actions
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(ServiceDriverRow {
                has_ts: false,
                sort_ts: 0,
                tie_key: key,
                row: output,
            });
        }

        for row in forensic_engine::classification::regservice::get_delayed_services_from_reg(
            &services_reg_path,
        ) {
            delayed_rows = delayed_rows.saturating_add(1);
            let output = serde_json::json!({
                "source": "service-delay",
                "event_type": "service-delayed-autostart",
                "timestamp_unix": serde_json::Value::Null,
                "timestamp_utc": serde_json::Value::Null,
                "timestamp_precision": "none",
                "severity": "info",
                "service_name": row.name,
                "service_name_canonical": row.name.to_ascii_lowercase(),
                "delayed_start": row.delayed_start
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(ServiceDriverRow {
                has_ts: false,
                sort_ts: 0,
                tie_key: key,
                row: output,
            });
        }

        for row in forensic_engine::classification::regservice::get_service_dll_entries_from_reg(
            &services_reg_path,
        ) {
            service_dll_rows = service_dll_rows.saturating_add(1);
            let dll_path = normalize_path(&row.dll_path);
            let host_image = row.host_image_path.as_deref().map(normalize_path);
            let output = serde_json::json!({
                "source": "service-dll",
                "event_type": "service-dll-entry",
                "timestamp_unix": serde_json::Value::Null,
                "timestamp_utc": serde_json::Value::Null,
                "timestamp_precision": "none",
                "severity": if row.suspicious { "warn" } else { "info" },
                "service_name": row.service,
                "service_name_canonical": row.service.to_ascii_lowercase(),
                "dll_path": dll_path,
                "service_main": row.service_main,
                "host_image_path": host_image,
                "suspicious": row.suspicious,
                "reasons": row.reasons,
                "executable_name": executable_name_from_hint(&dll_path)
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(ServiceDriverRow {
                has_ts: false,
                sort_ts: 0,
                tie_key: key,
                row: output,
            });
        }

        if out_rows.is_empty() {
            let fallback = parse_registry_text_fallback(&services_reg_path, "services-drivers");
            fallback_rows = fallback.len();
            for output in fallback {
                let key = powershell_record_dedupe_key(&output);
                if !seen_dedupe.insert(key.clone()) {
                    deduped_count = deduped_count.saturating_add(1);
                    continue;
                }
                out_rows.push(ServiceDriverRow {
                    has_ts: false,
                    sort_ts: 0,
                    tie_key: key,
                    row: output,
                });
            }
        }
    } else {
        warnings.push(format!(
            "Services/Drivers export not found: {}",
            services_reg_path.display()
        ));
    }

    if matches!(
        input_shape,
        forensic_engine::classification::regservice::ServiceDriverInputShape::Unknown
            | forensic_engine::classification::regservice::ServiceDriverInputShape::Binary
    ) {
        quality_flags.push("input_shape_unexpected_for_reg_parser".to_string());
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
    let suspicious_rows = out_rows
        .iter()
        .filter(|row| {
            row.row
                .get("suspicious")
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
        "input_path": services_reg_path.to_string_lossy().to_string(),
        "input_exists": services_reg_path.exists(),
        "limit": limit,
        "total_available": total_available,
        "total_returned": records.len(),
        "source_rows": {
            "service_config": config_rows,
            "service_failure": failure_rows,
            "delayed_services": delayed_rows,
            "service_dll": service_dll_rows
        },
        "summary": {
            "suspicious_rows": suspicious_rows,
            "timestamp_rows": timestamp_rows,
            "executable_rows": executable_rows
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "registry-services-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "source+service+path",
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
        println!("=== Services and Drivers Artifacts ===");
        println!(
            "Rows: config={} failure={} delayed={} service_dll={}",
            config_rows, failure_rows, delayed_rows, service_dll_rows
        );
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "services-drivers-artifacts",
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

// Extracted from main.rs — run_defender_artifacts_command
// TODO: Convert to clap derive args in a future pass

use crate::*;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "defender-artifacts",
    about = "Reads Defender-related artifacts from default/env-configured paths"
)]
pub struct DefenderArgs {
    #[arg(
        short,
        long,
        help = "Limit records returned per collection (default: 200, max: 5000)"
    )]
    pub limit: Option<String>,

    #[arg(short, long, help = "Print command payload as JSON")]
    pub json: bool,

    #[arg(long, help = "Write envelope JSON to file")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long, help = "Suppress console summary output")]
    pub quiet: bool,
}

pub fn execute(args: DefenderArgs, _command_name: &str, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let mut limit = match args.limit {
        Some(limit_str) => match limit_str.parse::<usize>() {
            Ok(parsed) => parsed,
            Err(_) => {
                let err_msg = format!("Error: Invalid --limit '{}'", limit_str);
                if let Some(ref json_path) = json_result_path {
                    let envelope = crate::envelope::CliResultEnvelope::new(
                        "defender-artifacts",
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
        None => crate::DEFENDER_ARTIFACTS_DEFAULT_LIMIT,
    };

    if limit == 0 {
        let err_msg = "Error: --limit must be greater than 0".to_string();
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "defender-artifacts",
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
    if limit > DEFENDER_ARTIFACTS_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, DEFENDER_ARTIFACTS_MAX_LIMIT
        ));
        limit = DEFENDER_ARTIFACTS_MAX_LIMIT;
    }

    let status = match get_defender_status() {
        Ok(v) => v,
        Err(e) => {
            warnings.push(format!("Unable to read Defender status: {}", e));
            forensic_engine::classification::DefenderStatus::default()
        }
    };
    let mut av_products = match get_av_products() {
        Ok(v) => v,
        Err(e) => {
            warnings.push(format!("Unable to read Defender AV products: {}", e));
            Vec::new()
        }
    };
    let exclusions = match get_defender_exclusions() {
        Ok(v) => v,
        Err(e) => {
            warnings.push(format!("Unable to read Defender exclusions: {}", e));
            Vec::new()
        }
    };
    let mut quarantined = match get_defender_quarantined_items() {
        Ok(v) => v,
        Err(e) => {
            warnings.push(format!("Unable to read Defender quarantine records: {}", e));
            Vec::new()
        }
    };
    let mut scans = match get_defender_scan_history() {
        Ok(v) => v,
        Err(e) => {
            warnings.push(format!("Unable to read Defender scan history: {}", e));
            Vec::new()
        }
    };
    let mut endpoint_alerts =
        forensic_engine::classification::defender_endpoint::get_defender_alerts();
    let mut endpoint_indicators =
        forensic_engine::classification::defender_endpoint::get_defender_indicators();
    let mut endpoint_file_profiles =
        forensic_engine::classification::defender_endpoint::get_defender_file_profiles();
    let mut endpoint_machine_actions =
        forensic_engine::classification::defender_endpoint::get_defender_machine_actions();

    let quarantine_source = env::var("FORENSIC_DEFENDER_QUARANTINE")
        .unwrap_or_else(|_| "artifacts/defender/quarantine.log".to_string());
    let scan_history_source = env::var("FORENSIC_DEFENDER_SCAN_HISTORY")
        .unwrap_or_else(|_| "artifacts/defender/scan_history.log".to_string());
    let alerts_source = env::var("FORENSIC_DEFENDER_ALERTS")
        .unwrap_or_else(|_| "artifacts/defender_endpoint/alerts.json".to_string());
    let indicators_source = env::var("FORENSIC_DEFENDER_INDICATORS")
        .unwrap_or_else(|_| "artifacts/defender_endpoint/indicators.json".to_string());
    let file_profiles_source = env::var("FORENSIC_DEFENDER_FILE_PROFILES")
        .unwrap_or_else(|_| "artifacts/defender_endpoint/file_profiles.json".to_string());
    let machine_actions_source = env::var("FORENSIC_DEFENDER_MACHINE_ACTIONS")
        .unwrap_or_else(|_| "artifacts/defender_endpoint/machine_actions.json".to_string());

    if quarantined.is_empty() && !PathBuf::from(&quarantine_source).exists() {
        warnings.push(format!(
            "Quarantine source not found: {}",
            quarantine_source
        ));
    }
    if scans.is_empty() && !PathBuf::from(&scan_history_source).exists() {
        warnings.push(format!(
            "Scan-history source not found: {}",
            scan_history_source
        ));
    }
    if endpoint_alerts.is_empty() && !PathBuf::from(&alerts_source).exists() {
        warnings.push(format!(
            "Endpoint alerts source not found: {}",
            alerts_source
        ));
    }
    if endpoint_indicators.is_empty() && !PathBuf::from(&indicators_source).exists() {
        warnings.push(format!(
            "Endpoint indicators source not found: {}",
            indicators_source
        ));
    }
    if endpoint_file_profiles.is_empty() && !PathBuf::from(&file_profiles_source).exists() {
        warnings.push(format!(
            "Endpoint file profiles source not found: {}",
            file_profiles_source
        ));
    }
    if endpoint_machine_actions.is_empty() && !PathBuf::from(&machine_actions_source).exists() {
        warnings.push(format!(
            "Endpoint machine-actions source not found: {}",
            machine_actions_source
        ));
    }

    av_products.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.publisher.cmp(&b.publisher))
    });
    quarantined.sort_by(|a, b| {
        b.quarantine_time
            .cmp(&a.quarantine_time)
            .then_with(|| a.threat_name.cmp(&b.threat_name))
            .then_with(|| a.file_path.cmp(&b.file_path))
    });
    scans.sort_by(|a, b| {
        b.end_time
            .unwrap_or(b.start_time)
            .cmp(&a.end_time.unwrap_or(a.start_time))
            .then_with(|| b.start_time.cmp(&a.start_time))
    });
    endpoint_alerts.sort_by(|a, b| {
        b.detected
            .cmp(&a.detected)
            .then_with(|| a.alert_id.cmp(&b.alert_id))
    });
    endpoint_indicators.sort_by(|a, b| {
        b.created
            .cmp(&a.created)
            .then_with(|| a.indicator_type.cmp(&b.indicator_type))
            .then_with(|| a.value.cmp(&b.value))
    });
    endpoint_file_profiles.sort_by(|a, b| {
        b.first_seen
            .cmp(&a.first_seen)
            .then_with(|| a.sha1.cmp(&b.sha1))
            .then_with(|| a.detection_name.cmp(&b.detection_name))
    });
    endpoint_machine_actions.sort_by(|a, b| {
        b.requested
            .cmp(&a.requested)
            .then_with(|| a.action_id.cmp(&b.action_id))
    });

    let scan_type_str = |scan_type: &forensic_engine::classification::ScanType| match scan_type {
        forensic_engine::classification::ScanType::Quick => "quick",
        forensic_engine::classification::ScanType::Full => "full",
        forensic_engine::classification::ScanType::Custom => "custom",
    };
    let scan_result_str = |result: &forensic_engine::classification::ScanResult| match result {
        forensic_engine::classification::ScanResult::Unknown => "unknown",
        forensic_engine::classification::ScanResult::Completed => "completed",
        forensic_engine::classification::ScanResult::Cancelled => "cancelled",
        forensic_engine::classification::ScanResult::Failed => "failed",
    };
    let av_type_str =
        |product_type: &forensic_engine::classification::AvProductType| match product_type {
            forensic_engine::classification::AvProductType::Antivirus => "antivirus",
            forensic_engine::classification::AvProductType::Antispyware => "antispyware",
            forensic_engine::classification::AvProductType::Firewall => "firewall",
            forensic_engine::classification::AvProductType::DeviceControl => "device_control",
        };
    let exclusion_type_str =
        |entry_type: &forensic_engine::classification::ExclusionType| match entry_type {
            forensic_engine::classification::ExclusionType::Path => "path",
            forensic_engine::classification::ExclusionType::Extension => "extension",
            forensic_engine::classification::ExclusionType::Process => "process",
        };
    let to_utc_u64 = |ts: u64| unix_seconds_to_utc(std::cmp::min(ts, i64::MAX as u64) as i64);

    let data = serde_json::json!({
        "limit": limit,
        "source_paths": {
            "quarantine": quarantine_source,
            "scan_history": scan_history_source,
            "alerts": alerts_source,
            "indicators": indicators_source,
            "file_profiles": file_profiles_source,
            "machine_actions": machine_actions_source
        },
        "status": {
            "enabled": status.enabled,
            "real_time_protection": status.real_time_protection,
            "behavior_monitoring": status.behavior_monitoring,
            "script_scanning": status.script_scanning,
            "cloud_protection": status.cloud_protection,
            "tamper_protection": status.tamper_protection,
            "signature_age_days": status.signature_age,
            "last_scan_unix": status.last_scan,
            "last_scan_utc": status.last_scan.map(to_utc_u64)
        },
        "counts": {
            "av_products_total": av_products.len(),
            "exclusions_total": exclusions.len(),
            "quarantine_total": quarantined.len(),
            "scan_history_total": scans.len(),
            "endpoint_alerts_total": endpoint_alerts.len(),
            "endpoint_indicators_total": endpoint_indicators.len(),
            "endpoint_file_profiles_total": endpoint_file_profiles.len(),
            "endpoint_machine_actions_total": endpoint_machine_actions.len(),
            "warning_count": warnings.len()
        },
        "av_products": av_products.into_iter().take(limit).map(|row| serde_json::json!({
            "name": row.name,
            "publisher": row.publisher,
            "version": row.version,
            "enabled": row.enabled,
            "real_time_protection": row.real_time_protection,
            "last_update_unix": row.last_update,
            "last_update_utc": row.last_update.map(to_utc_u64),
            "product_type": av_type_str(&row.product_type)
        })).collect::<Vec<_>>(),
        "exclusions": exclusions.into_iter().take(limit).map(|row| serde_json::json!({
            "exclusion_type": exclusion_type_str(&row.exclusion_type),
            "value": row.value
        })).collect::<Vec<_>>(),
        "quarantine_items": quarantined.into_iter().take(limit).map(|row| serde_json::json!({
            "threat_name": row.threat_name,
            "file_path": row.file_path,
            "quarantine_time_unix": row.quarantine_time,
            "quarantine_time_utc": Some(to_utc_u64(row.quarantine_time)),
            "original_threat_level": row.original_threat_level
        })).collect::<Vec<_>>(),
        "scan_history": scans.into_iter().take(limit).map(|row| serde_json::json!({
            "scan_type": scan_type_str(&row.scan_type),
            "start_time_unix": row.start_time,
            "start_time_utc": Some(to_utc_u64(row.start_time)),
            "end_time_unix": row.end_time,
            "end_time_utc": row.end_time.map(to_utc_u64),
            "threats_found": row.threats_found,
            "threats_resolved": row.threats_resolved,
            "scan_result": scan_result_str(&row.scan_result)
        })).collect::<Vec<_>>(),
        "endpoint": {
            "alerts": endpoint_alerts.into_iter().take(limit).map(|row| serde_json::json!({
                "alert_id": row.alert_id,
                "title": row.title,
                "severity": row.severity,
                "category": row.category,
                "detected_unix": row.detected,
                "detected_utc": if row.detected > 0 { Some(to_utc_u64(row.detected)) } else { None },
                "status": row.status,
                "machine_name": row.machine_name
            })).collect::<Vec<_>>(),
            "indicators": endpoint_indicators.into_iter().take(limit).map(|row| serde_json::json!({
                "indicator_type": row.indicator_type,
                "value": row.value,
                "action": row.action,
                "created_unix": row.created,
                "created_utc": if row.created > 0 { Some(to_utc_u64(row.created)) } else { None },
                "expiration_unix": row.expiration,
                "expiration_utc": if row.expiration > 0 { Some(to_utc_u64(row.expiration)) } else { None }
            })).collect::<Vec<_>>(),
            "file_profiles": endpoint_file_profiles.into_iter().take(limit).map(|row| serde_json::json!({
                "sha1": row.sha1,
                "detection_name": row.detection_name,
                "first_seen_unix": row.first_seen,
                "first_seen_utc": if row.first_seen > 0 { Some(to_utc_u64(row.first_seen)) } else { None },
                "prevalence": row.prevalence,
                "is_malicious": row.is_malicious
            })).collect::<Vec<_>>(),
            "machine_actions": endpoint_machine_actions.into_iter().take(limit).map(|row| serde_json::json!({
                "action_id": row.action_id,
                "machine_id": row.machine_id,
                "action_type": row.action_type,
                "requested_unix": row.requested,
                "requested_utc": if row.requested > 0 { Some(to_utc_u64(row.requested)) } else { None },
                "completed_unix": row.completed,
                "completed_utc": row.completed.map(to_utc_u64),
                "status": row.status
            })).collect::<Vec<_>>()
        }
    });

    if json_output && !quiet {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else if !quiet {
        println!("=== Defender Artifacts ===");
        println!(
            "Enabled: {} | Realtime: {} | Last Scan: {}",
            status.enabled,
            status.real_time_protection,
            status
                .last_scan
                .map(to_utc_u64)
                .unwrap_or_else(|| "n/a".to_string())
        );
        println!(
            "Counts: av_products={} exclusions={} quarantine={} scans={} endpoint_alerts={}",
            data["counts"]["av_products_total"].as_u64().unwrap_or(0),
            data["counts"]["exclusions_total"].as_u64().unwrap_or(0),
            data["counts"]["quarantine_total"].as_u64().unwrap_or(0),
            data["counts"]["scan_history_total"].as_u64().unwrap_or(0),
            data["counts"]["endpoint_alerts_total"]
                .as_u64()
                .unwrap_or(0)
        );
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "defender-artifacts",
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

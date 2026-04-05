// Extracted from main.rs - run_restore_shadow_copies_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "restore-shadow-copies",
    about = "Parse restore point / shadow copy artifact exports"
)]
pub struct RestoreShadowCopiesArgs {
    #[arg(
        long = "restore-input",
        alias = "input",
        aliases = ["shadow-input"]
    )]
    pub restore_input: Option<PathBuf>,

    #[arg(short, long)]
    pub limit: Option<usize>,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: RestoreShadowCopiesArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let input_path = args
        .restore_input
        .or_else(|| {
            env::var("FORENSIC_RESTORE_SHADOW_PATH")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("exports").join("restore_shadow.json"));
    let mut limit = args.limit.unwrap_or(RESTORE_SHADOW_COPIES_DEFAULT_LIMIT);
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    if limit == 0 {
        let err_msg = "Error: --limit must be greater than 0".to_string();
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "restore-shadow-copies",
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

    if limit > RESTORE_SHADOW_COPIES_MAX_LIMIT {
        limit = RESTORE_SHADOW_COPIES_MAX_LIMIT;
    }

    let input_shape =
        forensic_engine::classification::restore_shadow::detect_restore_shadow_input_shape(
            &input_path,
        );

    let mut warnings: Vec<String> = Vec::new();

    if input_path.exists() {
        let parsed =
            forensic_engine::classification::restore_shadow::parse_restore_shadow_records_from_path(
                &input_path,
                limit,
            );
        let total_available = parsed.len();
        let primary_rows = total_available;
        let fallback_rows = 0usize;
        let records = parsed
            .into_iter()
            .take(limit)
            .map(|row| {
                let severity = match row.event_type.as_str() {
                    "delete" | "deleted" | "removed" => "warn",
                    _ => "info",
                };
                serde_json::json!({
                    "source": row.source,
                    "event_type": row.event_type,
                    "restore_point_id": row.restore_point_id,
                    "snapshot_id": row.snapshot_id,
                    "name": row.name,
                    "description": row.description,
                    "restore_point_type": row.restore_point_type,
                    "file_path": row.file_path,
                    "change_type": row.change_type,
                    "status": row.status,
                    "integrity_ok": row.integrity_ok,
                    "timestamp_unix": row.timestamp_unix,
                    "timestamp_utc": row.timestamp_utc,
                    "timestamp_precision": row.timestamp_precision,
                    "user_sid": row.user_sid,
                    "username": row.username,
                    "source_path": row.source_path,
                    "source_record_id": row.source_record_id,
                    "severity": severity,
                })
            })
            .collect::<Vec<_>>();

        if total_available == 0 {
            warnings.push(format!(
                "No restore/shadow records parsed from {}",
                input_path.display()
            ));
        }

        let timestamp_rows = records
            .iter()
            .filter(|r| r.get("timestamp_unix").and_then(|v| v.as_i64()).is_some())
            .count();

        let data = serde_json::json!({
            "input_path": input_path.to_string_lossy().to_string(),
            "input_exists": true,
            "input_shape": input_shape.as_str(),
            "limit": limit,
            "total_available": total_available,
            "total_returned": records.len(),
            "source_rows": {
                "primary": primary_rows,
                "fallback": fallback_rows
            },
            "summary": {
                "timestamp_rows": timestamp_rows,
                "warning_count": warnings.len()
            },
            "quality": {
                "input_shape": input_shape.as_str(),
                "parser_mode": "restore_shadow_copies_v1",
                "warning_count": warnings.len()
            },
            "records": records,
        });

        if json_output && !quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            );
        } else if !quiet {
            println!("=== Restore / Shadow Copies ===");
            println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        }

        if let Some(ref json_path) = json_result_path {
            let mut envelope = CliResultEnvelope::new(
                "restore-shadow-copies",
                original_args,
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
    } else {
        warnings.push(format!(
            "Restore/shadow input not found: {}",
            input_path.display()
        ));
        let data = serde_json::json!({
            "input_path": input_path.to_string_lossy().to_string(),
            "input_exists": false,
            "input_shape": input_shape.as_str(),
            "limit": limit,
            "total_returned": 0,
            "records": [],
        });
        if json_output && !quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            );
        } else if !quiet {
            println!("No restore/shadow input found.");
        }
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "restore-shadow-copies",
                original_args,
                EXIT_VALIDATION,
                start_time.elapsed().as_millis() as u64,
            )
            .with_data(data)
            .warn(warnings.join("; "));
            let _ = envelope.write_to_file(json_path);
        }
        std::process::exit(EXIT_VALIDATION);
    }
}

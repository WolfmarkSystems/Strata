// Extracted from main.rs — run_evtx_sysmon_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "evtx-sysmon", about = "Parse Sysmon EVTX events")]
pub struct EvtxSysmonArgs {
    #[arg(long)]
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

pub fn execute(args: EvtxSysmonArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let input_path = args.input.unwrap_or_else(|| {
        env::var("FORENSIC_EVTX_SYSMON_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_evtx_sysmon_path())
    });
    let mut limit = EVTX_SYSMON_DEFAULT_LIMIT;
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
                        "evtx-sysmon",
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
                "evtx-sysmon",
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
    if limit > EVTX_SYSMON_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, EVTX_SYSMON_MAX_LIMIT
        ));
        limit = EVTX_SYSMON_MAX_LIMIT;
    }

    if !input_path.exists() {
        let err_msg = format!("Error: EVTX input not found: {}", input_path.display());
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "evtx-sysmon",
                original_args.clone(),
                EXIT_VALIDATION,
                start_time.elapsed().as_millis() as u64,
            )
            .error(err_msg.clone())
            .with_error_type("invalid_input")
            .with_hint("Provide --input <path> to Sysmon.evtx or an EVTX XML export");
            let _ = envelope.write_to_file(json_path);
        }
        if !quiet {
            eprintln!("{}", err_msg);
        }
        std::process::exit(EXIT_VALIDATION);
    }

    let parsed = match parse_system_log_with_metadata(&input_path) {
        Ok(result) => result,
        Err(e) => {
            let err_msg = format!(
                "Error parsing EVTX sysmon input {}: {}",
                input_path.display(),
                e
            );
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "evtx-sysmon",
                    original_args.clone(),
                    EXIT_ERROR,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("parse_error")
                .with_hint("Validate the Sysmon.evtx/XML source and retry");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                eprintln!("{}", err_msg);
            }
            std::process::exit(EXIT_ERROR);
        }
    };

    if parsed.entries.is_empty() {
        warnings.push("No EVTX sysmon events parsed from input.".to_string());
    }
    for flag in &parsed.metadata.quality_flags {
        warnings.push(format!("EVTX quality: {}", flag));
    }

    let process_create_events = parsed.entries.iter().filter(|e| e.event_id == 1).count();
    let network_connect_events = parsed.entries.iter().filter(|e| e.event_id == 3).count();
    let file_create_events = parsed.entries.iter().filter(|e| e.event_id == 11).count();
    let registry_events = parsed
        .entries
        .iter()
        .filter(|e| matches!(e.event_id, 12..=14))
        .count();
    let remote_thread_events = parsed.entries.iter().filter(|e| e.event_id == 8).count();
    let process_access_events = parsed.entries.iter().filter(|e| e.event_id == 10).count();

    let total_available = parsed.entries.len();
    let entries = parsed
        .entries
        .iter()
        .take(limit)
        .map(|row| {
            let severity = if row.event_id == 8 || row.event_id == 10 || row.event_id == 13 {
                "warn"
            } else if row.level <= 2 {
                "error"
            } else {
                "info"
            };
            serde_json::json!({
                "event_id": row.event_id,
                "level": row.level,
                "level_name": row.level_name,
                "severity": severity,
                "timestamp_unix": row.timestamp,
                "timestamp_utc": row.timestamp.map(unix_seconds_to_utc),
                "source": row.source,
                "channel": row.channel,
                "record_id": row.record_id,
                "task": row.task,
                "opcode": row.opcode,
                "keywords": row.keywords,
                "process_id": row.process_id,
                "thread_id": row.thread_id,
                "semantic_category": row.semantic_category,
                "semantic_summary": row.semantic_summary,
                "message": row.message,
                "computer": row.computer,
                "user": row.user,
                "event_data": row.event_data
            })
        })
        .collect::<Vec<_>>();

    let data = serde_json::json!({
        "input_path": input_path.to_string_lossy().to_string(),
        "input_exists": true,
        "limit": limit,
        "total_available": total_available,
        "total_returned": entries.len(),
        "summary": {
            "process_create_events": process_create_events,
            "network_connect_events": network_connect_events,
            "file_create_events": file_create_events,
            "registry_events": registry_events,
            "remote_thread_events": remote_thread_events,
            "process_access_events": process_access_events
        },
        "quality": {
            "input_shape": parsed.metadata.input_shape.as_str(),
            "parser_mode": parsed.metadata.parser_mode,
            "fallback_used": parsed.metadata.fallback_used,
            "deduped_count": parsed.metadata.deduped_count,
            "quality_flags": parsed.metadata.quality_flags
        },
        "entries": entries
    });

    if json_output && !quiet {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else if !quiet {
        println!("=== EVTX Sysmon Events ===");
        println!("Input: {}", input_path.display());
        println!("Total available: {}", total_available);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        println!(
            "Summary: process_create={} network={} file_create={} registry={} remote_thread={} process_access={}",
            process_create_events,
            network_connect_events,
            file_create_events,
            registry_events,
            remote_thread_events,
            process_access_events
        );
        if let Some(rows) = data["entries"].as_array() {
            for row in rows.iter().take(20) {
                let ts = row["timestamp_utc"].as_str().unwrap_or("n/a");
                let event_id = row["event_id"].as_u64().unwrap_or(0);
                let desc = row["semantic_summary"]
                    .as_str()
                    .unwrap_or_else(|| row["source"].as_str().unwrap_or("event"));
                println!("[{}] event={} {}", ts, event_id, desc);
            }
            if rows.len() > 20 {
                println!("... ({} more rows)", rows.len() - 20);
            }
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "evtx-sysmon",
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

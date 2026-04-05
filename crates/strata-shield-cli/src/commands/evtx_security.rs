// Extracted from main.rs — run_evtx_security_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "evtx-security", about = "Parse Security EVTX events")]
pub struct EvtxSecurityArgs {
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

pub fn execute(args: EvtxSecurityArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let input_path = args.input.unwrap_or_else(|| {
        env::var("FORENSIC_EVTX_SECURITY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_evtx_security_path())
    });
    let mut limit = EVTX_SECURITY_DEFAULT_LIMIT;
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
                        "evtx-security",
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
                "evtx-security",
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
    if limit > EVTX_SECURITY_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, EVTX_SECURITY_MAX_LIMIT
        ));
        limit = EVTX_SECURITY_MAX_LIMIT;
    }

    if !input_path.exists() {
        let err_msg = format!("Error: EVTX input not found: {}", input_path.display());
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "evtx-security",
                original_args.clone(),
                EXIT_VALIDATION,
                start_time.elapsed().as_millis() as u64,
            )
            .error(err_msg.clone())
            .with_error_type("invalid_input")
            .with_hint("Provide --input <path> to Security.evtx or an EVTX XML export");
            let _ = envelope.write_to_file(json_path);
        }
        if !quiet {
            eprintln!("{}", err_msg);
        }
        std::process::exit(EXIT_VALIDATION);
    }

    let parsed = match parse_security_log_with_metadata(&input_path) {
        Ok(result) => result,
        Err(e) => {
            let err_msg = format!(
                "Error parsing EVTX security input {}: {}",
                input_path.display(),
                e
            );
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "evtx-security",
                    original_args.clone(),
                    EXIT_ERROR,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("parse_error")
                .with_hint("Validate the Security.evtx/XML source and retry");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                eprintln!("{}", err_msg);
            }
            std::process::exit(EXIT_ERROR);
        }
    };

    if parsed.summary.entries.is_empty() {
        warnings.push("No EVTX security events parsed from input.".to_string());
    }
    for flag in &parsed.metadata.quality_flags {
        warnings.push(format!("EVTX quality: {}", flag));
    }

    let total_available = parsed.summary.entries.len();
    let entries = parsed
        .summary
        .entries
        .iter()
        .take(limit)
        .map(|row| {
            let severity = if row.level <= 2 {
                "error"
            } else if row.level == 3 {
                "warn"
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
            "logon_events": parsed.summary.logon_events,
            "failed_logons": parsed.summary.failed_logons,
            "privilege_escalation": parsed.summary.privilege_escalation,
            "account_changes": parsed.summary.account_changes
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
        println!("=== EVTX Security Events ===");
        println!("Input: {}", input_path.display());
        println!("Total available: {}", total_available);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        println!(
            "Summary: logon={} failed={} privilege={} account_changes={}",
            parsed.summary.logon_events,
            parsed.summary.failed_logons,
            parsed.summary.privilege_escalation,
            parsed.summary.account_changes
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
            "evtx-security",
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

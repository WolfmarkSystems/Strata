// Extracted from main.rs — run_scheduled_tasks_artifacts_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "scheduled-tasks-artifacts",
    about = "Parse scheduled task artifacts"
)]
pub struct ScheduledTasksArtifactsArgs {
    #[arg(long = "tasks-root", alias = "input")]
    pub tasks_root: Option<PathBuf>,

    #[arg(short, long)]
    pub limit: Option<String>,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: ScheduledTasksArtifactsArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let tasks_root = args
        .tasks_root
        .unwrap_or_else(|| PathBuf::from("exports").join("tasks"));
    let mut limit = SCHEDULED_TASKS_DEFAULT_LIMIT;
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
                        "scheduled-tasks-artifacts",
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
                "scheduled-tasks-artifacts",
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
    if limit > SCHEDULED_TASKS_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, SCHEDULED_TASKS_MAX_LIMIT
        ));
        limit = SCHEDULED_TASKS_MAX_LIMIT;
    }

    #[derive(Clone)]
    struct ScheduledTaskRow {
        has_ts: bool,
        sort_ts: i64,
        tie_key: String,
        row: serde_json::Value,
    }

    let input_shape =
        forensic_engine::classification::scheduledtasks::detect_scheduled_tasks_input_shape(
            &tasks_root,
        );
    let mut out_rows: Vec<ScheduledTaskRow> = Vec::new();
    let mut primary_rows = 0usize;
    let mut fallback_rows = 0usize;
    let mut deduped_count = 0usize;
    let mut quality_flags: Vec<String> = Vec::new();
    let mut seen_dedupe: std::collections::HashSet<String> = std::collections::HashSet::new();

    let normalize_path = |value: &str| value.trim().trim_matches('"').replace('/', "\\");

    let mut tasks = if tasks_root.exists() {
        parse_scheduled_tasks_xml(&tasks_root).unwrap_or_else(|_| Vec::new())
    } else {
        warnings.push(format!(
            "Scheduled tasks root not found: {}",
            tasks_root.display()
        ));
        Vec::new()
    };

    if tasks.is_empty() && tasks_root.exists() {
        let fallback =
            forensic_engine::classification::scheduledtasks::parse_scheduled_tasks_text_fallback(
                &tasks_root,
            );
        fallback_rows = fallback.len();
        tasks = fallback;
    }

    for task in tasks {
        primary_rows = primary_rows.saturating_add(1);
        let ts = task.last_run_time.or(task.next_run_time);
        let task_path = normalize_path(&task.path);
        let task_state = match task.state {
            forensic_engine::classification::TaskState::Ready => "ready",
            forensic_engine::classification::TaskState::Running => "running",
            forensic_engine::classification::TaskState::Disabled => "disabled",
            forensic_engine::classification::TaskState::Queued => "queued",
            forensic_engine::classification::TaskState::Unknown => "unknown",
        };

        if task.actions.is_empty() {
            let output = serde_json::json!({
                "source": if fallback_rows > 0 { "task-text-fallback" } else { "task-xml" },
                "event_type": "scheduled-task",
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc),
                "timestamp_precision": if ts.is_some() { "seconds" } else { "none" },
                "severity": if task_state == "disabled" { "warn" } else { "info" },
                "task_name": task.name,
                "task_path": task_path,
                "task_state": task_state,
                "author": task.author,
                "description": task.description,
                "trigger_count": task.triggers.len(),
                "action_count": 0,
                "executable_name": serde_json::Value::Null
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(ScheduledTaskRow {
                has_ts: ts.is_some(),
                sort_ts: ts.unwrap_or_default(),
                tie_key: key,
                row: output,
            });
            continue;
        }

        for (idx, action) in task.actions.iter().enumerate() {
            let action_type = match action.action_type {
                forensic_engine::classification::ActionType::Execute => "execute",
                forensic_engine::classification::ActionType::ComObject => "com-object",
                forensic_engine::classification::ActionType::Unknown => "unknown",
            };
            let command_path = action.path.as_deref().map(normalize_path);
            let output = serde_json::json!({
                "source": if fallback_rows > 0 { "task-text-fallback" } else { "task-xml" },
                "event_type": "scheduled-task-action",
                "timestamp_unix": ts,
                "timestamp_utc": ts.map(unix_seconds_to_utc),
                "timestamp_precision": if ts.is_some() { "seconds" } else { "none" },
                "severity": if task_state == "disabled" || action_type == "com-object" { "warn" } else { "info" },
                "task_name": task.name,
                "task_path": task_path,
                "task_state": task_state,
                "author": task.author,
                "description": task.description,
                "trigger_count": task.triggers.len(),
                "action_index": idx,
                "action_type": action_type,
                "command_path": command_path,
                "arguments": action.arguments,
                "executable_name": command_path.as_deref().and_then(executable_name_from_hint)
            });
            let key = powershell_record_dedupe_key(&output);
            if !seen_dedupe.insert(key.clone()) {
                deduped_count = deduped_count.saturating_add(1);
                continue;
            }
            out_rows.push(ScheduledTaskRow {
                has_ts: ts.is_some(),
                sort_ts: ts.unwrap_or_default(),
                tie_key: key,
                row: output,
            });
        }
    }

    if matches!(
        input_shape,
        forensic_engine::classification::scheduledtasks::ScheduledTaskInputShape::Unknown
            | forensic_engine::classification::scheduledtasks::ScheduledTaskInputShape::Binary
    ) {
        quality_flags.push("input_shape_unexpected_for_xml_parser".to_string());
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

    let total_available = out_rows.len();
    let records = out_rows
        .into_iter()
        .take(limit)
        .map(|v| v.row)
        .collect::<Vec<_>>();

    let data = serde_json::json!({
        "input_path": tasks_root.to_string_lossy().to_string(),
        "input_exists": tasks_root.exists(),
        "limit": limit,
        "total_available": total_available,
        "total_returned": records.len(),
        "source_rows": {
            "primary": primary_rows,
            "fallback": fallback_rows
        },
        "quality": {
            "input_shape": input_shape.as_str(),
            "parser_mode": "task-xml-merge",
            "fallback_used": fallback_rows > 0,
            "fallback_rows": fallback_rows,
            "deduped_count": deduped_count,
            "dedupe_reason": "task_path+action+timestamp",
            "timestamp_rows": timestamp_rows,
            "executable_rows": executable_rows,
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
        println!("=== Scheduled Tasks Artifacts ===");
        println!("Rows: primary={} fallback={}", primary_rows, fallback_rows);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if !warnings.is_empty() {
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "scheduled-tasks-artifacts",
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

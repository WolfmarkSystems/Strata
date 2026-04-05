// Extracted from main.rs — run_registry_persistence_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "registry-persistence",
    about = "Correlate persistence artifacts from registry/task inputs"
)]
pub struct RegistryPersistenceArgs {
    #[arg(long = "autorun-reg")]
    pub autorun_reg: Option<PathBuf>,

    #[arg(long = "bam-reg")]
    pub bam_reg: Option<PathBuf>,

    #[arg(long = "amcache-reg")]
    pub amcache_reg: Option<PathBuf>,

    #[arg(long = "tasks-root")]
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

pub fn execute(args: RegistryPersistenceArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let autorun_reg_path = args
        .autorun_reg
        .unwrap_or_else(|| PathBuf::from("exports").join("autorun.reg"));
    let bam_reg_path = args
        .bam_reg
        .unwrap_or_else(|| PathBuf::from("exports").join("bam.reg"));
    let amcache_reg_path = args
        .amcache_reg
        .unwrap_or_else(|| PathBuf::from("exports").join("amcache.reg"));
    let mut tasks_root_path = args.tasks_root;
    let mut limit = REGISTRY_PERSISTENCE_DEFAULT_LIMIT;
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    if let Some(limit_raw) = args.limit {
        match limit_raw.parse::<usize>() {
            Ok(parsed) => {
                limit = parsed.clamp(1, REGISTRY_PERSISTENCE_MAX_LIMIT);
            }
            Err(_) => {
                let err_msg = format!("Error: Invalid --limit '{}'", limit_raw);
                eprintln!("{}", err_msg);
                if let Some(ref json_path) = json_result_path {
                    let envelope = CliResultEnvelope::new(
                        "registry-persistence",
                        original_args.clone(),
                        EXIT_VALIDATION,
                        start_time.elapsed().as_millis() as u64,
                    )
                    .error(err_msg.clone())
                    .with_error_type("invalid_argument")
                    .with_hint("Use --limit <N> with a numeric value");
                    let _ = envelope.write_to_file(json_path);
                }
                std::process::exit(EXIT_VALIDATION);
            }
        }
    }

    if tasks_root_path.is_none() {
        tasks_root_path = env::var("FORENSIC_TASKS_ROOT").ok().map(PathBuf::from);
    }

    let mut warnings: Vec<String> = Vec::new();
    let autorun_shape = detect_registry_input_shape(&autorun_reg_path);
    let bam_shape = detect_registry_input_shape(&bam_reg_path);
    let amcache_shape = detect_registry_input_shape(&amcache_reg_path);
    let tasks_shape = if let Some(root) = tasks_root_path.as_ref() {
        if root.exists() && root.is_dir() {
            "directory"
        } else if root.exists() {
            "non-directory"
        } else {
            "missing"
        }
    } else {
        "unset"
    };
    let autoruns = if autorun_reg_path.exists() {
        forensic_engine::classification::autorun::get_auto_run_keys_from_reg(&autorun_reg_path)
    } else {
        warnings.push(format!(
            "Autorun export not found: {}",
            autorun_reg_path.display()
        ));
        Vec::new()
    };

    let bam = if bam_reg_path.exists() {
        forensic_engine::classification::regbam::get_bam_state_from_reg(&bam_reg_path)
    } else {
        warnings.push(format!(
            "BAM/DAM export not found: {}",
            bam_reg_path.display()
        ));
        Vec::new()
    };

    let tasks = if let Some(root) = tasks_root_path.as_ref() {
        if root.exists() {
            match parse_scheduled_tasks_xml(root) {
                Ok(rows) => rows,
                Err(e) => {
                    warnings.push(format!(
                        "Could not parse scheduled tasks from {}: {}",
                        root.display(),
                        e
                    ));
                    Vec::new()
                }
            }
        } else {
            warnings.push(format!(
                "Scheduled tasks root not found: {}",
                root.display()
            ));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let amcache = if amcache_reg_path.exists() {
        forensic_engine::classification::amcache::get_amcache_file_entries_from_reg(
            &amcache_reg_path,
        )
        .unwrap_or_else(|e| {
            warnings.push(format!(
                "Could not parse Amcache export from {}: {}",
                amcache_reg_path.display(),
                e
            ));
            Vec::new()
        })
    } else {
        warnings.push(format!(
            "Amcache export not found: {}",
            amcache_reg_path.display()
        ));
        Vec::new()
    };

    let all_rows = build_persistence_correlations_with_amcache(&autoruns, &tasks, &bam, &amcache);
    let total_available = all_rows.len();
    let correlations = all_rows
        .into_iter()
        .take(limit)
        .map(|row| {
            let mut source_confidence = serde_json::Map::new();
            if row.autorun_count > 0 {
                source_confidence.insert(
                    "autorun".to_string(),
                    serde_json::Value::String("medium".to_string()),
                );
            }
            if row.scheduled_task_count > 0 {
                source_confidence.insert(
                    "scheduled-task".to_string(),
                    serde_json::Value::String("medium".to_string()),
                );
            }
            if row.bam_count > 0 {
                source_confidence.insert(
                    "bam".to_string(),
                    serde_json::Value::String("high".to_string()),
                );
            }
            if row.dam_count > 0 {
                source_confidence.insert(
                    "dam".to_string(),
                    serde_json::Value::String("high".to_string()),
                );
            }
            if row.amcache_count > 0 {
                source_confidence.insert(
                    "amcache".to_string(),
                    serde_json::Value::String("medium".to_string()),
                );
            }
            serde_json::json!({
                "executable_path": row.executable_path,
                "sources": row.sources,
                "autorun_count": row.autorun_count,
                "scheduled_task_count": row.scheduled_task_count,
                "bam_count": row.bam_count,
                "dam_count": row.dam_count,
                "amcache_count": row.amcache_count,
                "overall_confidence": row.overall_confidence,
                "correlation_reasons": row.reason_codes,
                "source_confidence": source_confidence,
                "latest_execution_unix": row.latest_execution_unix,
                "latest_execution_utc": row.latest_execution_unix.map(|ts| unix_seconds_to_utc(ts as i64)),
            })
        })
        .collect::<Vec<_>>();

    if correlations.is_empty() && warnings.is_empty() {
        warnings.push(
            "No persistence correlations found from provided registry/task sources".to_string(),
        );
    }

    let bam_rows = bam
        .iter()
        .filter(|entry| !entry.source.eq_ignore_ascii_case("dam"))
        .count();
    let dam_rows = bam
        .iter()
        .filter(|entry| entry.source.eq_ignore_ascii_case("dam"))
        .count();

    let data = serde_json::json!({
        "limit": limit,
        "total_available": total_available,
        "total_returned": correlations.len(),
        "inputs": {
            "autorun_reg_path": autorun_reg_path.to_string_lossy().to_string(),
            "autorun_reg_found": autorun_reg_path.exists(),
            "bam_reg_path": bam_reg_path.to_string_lossy().to_string(),
            "bam_reg_found": bam_reg_path.exists(),
            "amcache_reg_path": amcache_reg_path.to_string_lossy().to_string(),
            "amcache_reg_found": amcache_reg_path.exists(),
            "tasks_root_path": tasks_root_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            "tasks_root_found": tasks_root_path.as_ref().map(|p| p.exists()),
        },
        "source_rows": {
            "autorun": autoruns.len(),
            "scheduled_tasks": tasks.len(),
            "bam": bam_rows,
            "dam": dam_rows,
            "amcache": amcache.len(),
        },
        "quality": {
            "input_shapes": {
                "autorun": autorun_shape.as_str(),
                "bam": bam_shape.as_str(),
                "amcache": amcache_shape.as_str(),
                "tasks": tasks_shape,
            },
            "parser_mode": "registry-export-merge",
            "fallback_used": false,
            "deduped_count": 0,
            "dedupe_reason": "executable_path",
            "warning_count": warnings.len(),
            "quality_flags": Vec::<String>::new()
        },
        "correlations": correlations,
    });

    let warning = if warnings.is_empty() {
        None
    } else {
        Some(warnings.join("; "))
    };

    if json_output && !quiet {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else if !quiet {
        println!("=== Registry Persistence Correlations ===");
        println!("Autorun rows: {}", autoruns.len());
        println!("Scheduled task rows: {}", tasks.len());
        println!("BAM rows: {}", bam_rows);
        println!("DAM rows: {}", dam_rows);
        println!("Amcache rows: {}", amcache.len());
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if let Some(rows) = data["correlations"].as_array() {
            for row in rows.iter().take(20) {
                let path = row["executable_path"].as_str().unwrap_or_default();
                let sources = row["sources"]
                    .as_array()
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                let latest = row["latest_execution_utc"].as_str().unwrap_or("n/a");
                let confidence = row["overall_confidence"].as_str().unwrap_or("n/a");
                println!("[{}] [{}] {} ({})", latest, confidence, path, sources);
            }
            if rows.len() > 20 {
                println!("... ({} more rows)", rows.len() - 20);
            }
        }
        if let Some(ref w) = warning {
            println!("Warning: {}", w);
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "registry-persistence",
            original_args.clone(),
            EXIT_OK,
            start_time.elapsed().as_millis() as u64,
        )
        .with_data(data);

        if let Some(w) = warning {
            envelope = envelope.warn(w);
        }

        let _ = envelope.write_to_file(json_path);
    }

    std::process::exit(EXIT_OK);
}

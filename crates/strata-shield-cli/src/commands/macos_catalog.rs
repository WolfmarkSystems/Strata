// Extracted from main.rs — run_macos_catalog_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "macos-catalog", about = "macOS artifact catalog operations")]
pub struct MacosCatalogArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn execute(args: MacosCatalogArgs) {
    let mut command_args = vec!["macos-catalog".to_string()];
    command_args.extend(args.args);
    execute_legacy(command_args);
}

fn execute_legacy(mut args: Vec<String>) {
    let start_time = std::time::Instant::now();
    args.remove(0);

    let mut list_only = false;
    let mut selected_key: Option<String> = None;
    let mut limit = MACOS_CATALOG_DEFAULT_LIMIT;
    let mut json_output = false;
    let mut json_result_path: Option<PathBuf> = None;
    let mut quiet = false;
    let original_args = args.clone();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--list" => {
                list_only = true;
                i += 1;
            }
            "--key" | "-k" => {
                if i + 1 < args.len() {
                    selected_key = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--limit" | "-l" => {
                if i + 1 < args.len() {
                    if let Ok(n) = args[i + 1].parse::<usize>() {
                        limit = n;
                        i += 2;
                    } else {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            "--json" | "-j" => {
                json_output = true;
                i += 1;
            }
            "--json-result" => {
                if i + 1 < args.len() {
                    json_result_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--quiet" | "-q" => {
                quiet = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!("Usage: forensic_cli macos-catalog [options]");
                println!();
                println!("Options:");
                println!("  --list             List available macOS catalog artifact keys");
                println!("  --key, -k <id>     Parse only one artifact key");
                println!(
                    "  --limit, -l <N>    Limit records returned (default: {}, max: {})",
                    MACOS_CATALOG_DEFAULT_LIMIT, MACOS_CATALOG_MAX_LIMIT
                );
                println!("  --json, -j         Print command payload as JSON");
                println!("  --json-result <file>  Write JSON result envelope to file");
                println!("  --quiet, -q        Suppress console output");
                std::process::exit(EXIT_OK);
            }
            _ => {
                i += 1;
            }
        }
    }

    if limit == 0 {
        let err_msg = "Error: --limit must be greater than 0".to_string();
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "macos-catalog",
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
            println!("{}", err_msg);
        }
        std::process::exit(EXIT_VALIDATION);
    }

    let mut warning: Option<String> = None;
    if limit > MACOS_CATALOG_MAX_LIMIT {
        warning = Some(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, MACOS_CATALOG_MAX_LIMIT
        ));
        limit = MACOS_CATALOG_MAX_LIMIT;
    }

    let specs = macos_catalog_specs();
    if let Some(ref key) = selected_key {
        if !specs.iter().any(|spec| spec.key == *key) {
            let err_msg = format!("Error: Unknown macOS catalog key '{}'", key);
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "macos-catalog",
                    original_args.clone(),
                    EXIT_VALIDATION,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("invalid_input")
                .with_hint("Use --list to view valid macOS catalog keys");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_VALIDATION);
        }
    }

    let selected_specs: Vec<&_> = match selected_key.as_ref() {
        Some(key) => specs.iter().filter(|spec| spec.key == *key).collect(),
        None => specs.iter().collect(),
    };

    let mut records = if list_only {
        Vec::new()
    } else if let Some(ref key) = selected_key {
        parse_macos_catalog_artifact(key)
    } else {
        parse_all_macos_catalog_artifacts()
    };

    records.sort_by(|a, b| {
        b.timestamp_unix
            .unwrap_or(0)
            .cmp(&a.timestamp_unix.unwrap_or(0))
            .then_with(|| a.artifact_key.cmp(&b.artifact_key))
            .then_with(|| a.primary.cmp(&b.primary))
    });
    if records.len() > limit {
        records.truncate(limit);
    }

    let mut counts_by_artifact = std::collections::BTreeMap::new();
    for record in &records {
        *counts_by_artifact
            .entry(record.artifact_key.clone())
            .or_insert(0usize) += 1;
    }

    let specs_json: Vec<serde_json::Value> = selected_specs
        .iter()
        .map(|spec| {
            serde_json::json!({
                "key": spec.key,
                "description": spec.description,
                "format": match spec.format {
                    MacosCatalogFormat::Sqlite => "sqlite",
                    MacosCatalogFormat::TextLines => "text_lines",
                },
                "env_key": spec.env_key,
                "candidates": spec.candidates,
            })
        })
        .collect();

    let records_json: Vec<serde_json::Value> = records
        .iter()
        .map(|record| {
            serde_json::json!({
                "artifact_key": record.artifact_key,
                "source_path": record.source_path,
                "timestamp_unix": record.timestamp_unix,
                "timestamp_utc": record.timestamp_unix.map(|ts| unix_seconds_to_utc(ts as i64)),
                "primary": record.primary,
                "secondary": record.secondary,
                "detail": record.detail,
                "fields_json": record.fields_json,
            })
        })
        .collect();

    let mode = if list_only { "list" } else { "scan" };
    let payload = serde_json::json!({
        "mode": mode,
        "selected_key": selected_key,
        "limit": limit,
        "total_specs": specs.len(),
        "selected_specs_count": selected_specs.len(),
        "total_records": records_json.len(),
        "counts_by_artifact": counts_by_artifact,
        "specs": specs_json,
        "records": records_json,
        "generated_utc": now_utc_rfc3339_nanos(),
    });

    if json_output {
        if !quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
        }
    } else if !quiet {
        println!("=== macOS Artifact Catalog ===");
        println!("Mode: {}", mode);
        println!("Total Specs: {}", specs.len());
        println!("Selected Specs: {}", selected_specs.len());
        if let Some(ref key) = selected_key {
            println!("Selected Key: {}", key);
        }
        println!("Returned Records: {}", records.len());
        println!();

        if list_only {
            for spec in selected_specs.iter().take(limit) {
                let format_label = match spec.format {
                    MacosCatalogFormat::Sqlite => "sqlite",
                    MacosCatalogFormat::TextLines => "text_lines",
                };
                println!("- {} [{}] {}", spec.key, format_label, spec.description);
            }
            if selected_specs.len() > limit {
                println!("... ({} more keys)", selected_specs.len() - limit);
            }
        } else if records.is_empty() {
            println!("No records found for selected catalog scope.");
        } else {
            for record in records.iter().take(20) {
                let ts = record
                    .timestamp_unix
                    .map(|ts| unix_seconds_to_utc(ts as i64))
                    .unwrap_or_else(|| "unknown-time".to_string());
                println!("[{}] {} -> {}", ts, record.artifact_key, record.primary);
            }
            if records.len() > 20 {
                println!("... ({} more records)", records.len() - 20);
            }
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "macos-catalog",
            original_args.clone(),
            EXIT_OK,
            start_time.elapsed().as_millis() as u64,
        )
        .with_data(payload);

        if let Some(w) = warning {
            envelope = envelope.warn(w);
        }

        if let Err(e) = envelope.write_to_file(json_path) {
            eprintln!("Error writing JSON result: {}", e);
            std::process::exit(EXIT_ERROR);
        }
    }

    std::process::exit(EXIT_OK);
}

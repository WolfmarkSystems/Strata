use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use tauri::{Emitter, Manager};

mod ai_audit;
use ai_audit::AiInteractionLog;

const SIDECAR_NAME: &str = "forensic_cli-x86_64-pc-windows-msvc.exe";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CliResultEnvelope {
    pub tool_version: String,
    pub timestamp_utc: String,
    pub platform: String,
    pub command: String,
    pub args: Vec<String>,
    pub status: String,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<std::collections::HashMap<String, Option<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sizes: Option<std::collections::HashMap<String, u64>>,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CliRunResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub envelope_json: Option<CliResultEnvelope>,
    pub json_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GuardianWarningEvent {
    pub command: String,
    pub warning: String,
    pub timestamp: String,
}

#[tauri::command]
async fn run_cli(args: Vec<String>, app_handle: tauri::AppHandle) -> Result<CliRunResult, String> {
    let app_data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {}", e))?;
    
    std::fs::create_dir_all(&app_data_dir)
        .map_err(|e| format!("Failed to create app data dir: {}", e))?;
    
    let json_filename = format!("cli_result_{}.json", 
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis());
    let json_path = app_data_dir.join(json_filename);
    
    if let Some(parent) = json_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create JSON parent dir: {}", e))?;
    }
    
    let mut cmd_args = args.clone();
    
    if !cmd_args.contains(&"--json-result".to_string()) {
        cmd_args.push("--json-result".to_string());
        cmd_args.push(json_path.to_string_lossy().to_string());
    }
    
    if !cmd_args.contains(&"--quiet".to_string()) && !cmd_args.contains(&"-q".to_string()) {
        cmd_args.push("--quiet".to_string());
    }
    
    log::info!("Running forensic_cli with args: {:?}", cmd_args);
    
    let cli_path = find_sidecar_path(&app_handle)?;
    
    log::info!("Using CLI path: {:?}", cli_path);
    
    let output = tokio::process::Command::new(&cli_path)
        .args(&cmd_args)
        .output()
        .await
        .map_err(|e| format!("Failed to run CLI at '{}': {}", cli_path.display(), e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    
    let envelope_json = if json_path.exists() {
        match std::fs::read_to_string(&json_path) {
            Ok(content) => {
                match serde_json::from_str::<CliResultEnvelope>(&content) {
                    Ok(envelope) => Some(envelope),
                    Err(e) => {
                        log::warn!("Failed to parse JSON envelope: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to read JSON result file: {}", e);
                None
            }
        }
    } else {
        log::warn!("JSON result file not found at: {:?}", json_path);
        None
    };

    if let Some(envelope) = envelope_json.as_ref() {
        if let Some(warning) = envelope.warning.as_ref() {
            let command_name = if envelope.command.trim().is_empty() {
                args.first()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string())
            } else {
                envelope.command.clone()
            };

            if let Err(e) = app_handle.emit(
                "guardian-warning",
                GuardianWarningEvent {
                    command: command_name,
                    warning: warning.clone(),
                    timestamp: envelope.timestamp_utc.clone(),
                },
            ) {
                log::warn!("Failed to emit guardian-warning event: {}", e);
            }
        }
    }

    Ok(CliRunResult {
        exit_code,
        stdout,
        stderr,
        envelope_json,
        json_path: Some(json_path.to_string_lossy().to_string()),
    })
}

fn sidecar_candidates(app_handle: &tauri::AppHandle) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    let mut push_candidate = |path: PathBuf| {
        let key = path.to_string_lossy().to_string().to_lowercase();
        if seen.insert(key) {
            candidates.push(path);
        }
    };

    // Allow explicit override for deterministic troubleshooting/build environments.
    if let Ok(override_path) = std::env::var("FORENSIC_CLI_SIDECAR_PATH") {
        let override_trimmed = override_path.trim();
        if !override_trimmed.is_empty() {
            push_candidate(PathBuf::from(override_trimmed));
        }
    }

    // Packaged app: resources are bundled under resource_dir, typically with resources/bin.
    if let Ok(resource_dir) = app_handle.path().resource_dir() {
        push_candidate(resource_dir.join("bin").join(SIDECAR_NAME));
        push_candidate(resource_dir.join(SIDECAR_NAME));
    }

    // Portable/unpacked app: sidecar may be next to exe or in exe_dir/bin.
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            push_candidate(exe_dir.join("bin").join(SIDECAR_NAME));
            push_candidate(exe_dir.join(SIDECAR_NAME));
            if let Some(parent) = exe_dir.parent() {
                push_candidate(parent.join("bin").join(SIDECAR_NAME));
                push_candidate(parent.join(SIDECAR_NAME));
            }
        }
    }

    // Development fallbacks.
    push_candidate(PathBuf::from("src-tauri").join("bin").join(SIDECAR_NAME));
    if let Ok(cwd) = std::env::current_dir() {
        push_candidate(cwd.join("src-tauri").join("bin").join(SIDECAR_NAME));
        push_candidate(cwd.join("bin").join(SIDECAR_NAME));
    }

    candidates
}

fn find_sidecar_path(app_handle: &tauri::AppHandle) -> Result<PathBuf, String> {
    let candidates = sidecar_candidates(app_handle);
    for path in &candidates {
        if path.is_file() {
            return Ok(path.clone());
        }
    }

    let tried = candidates
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "Sidecar '{}' was not found. Checked: {}",
        SIDECAR_NAME, tried
    ))
}

#[tauri::command]
fn get_cli_path(app_handle: tauri::AppHandle) -> String {
    find_sidecar_path(&app_handle)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| SIDECAR_NAME.to_string())
}

/// KB Bridge health check — Tier 1, operation_type: health_check.
/// Audit log entry is written BEFORE the bridge call per AI_AUDIT_TRAIL.md §7.1.
#[tauri::command]
async fn kb_bridge_health(
    case_id: Option<String>,
    examiner_id: Option<String>,
    app_handle: tauri::AppHandle,
) -> Result<CliRunResult, String> {
    let cid = case_id.as_deref().unwrap_or("NO_CASE");
    let eid = examiner_id.as_deref().unwrap_or("DEFAULT_UNSET");

    // Write audit entry BEFORE inference
    let mut log_entry = AiInteractionLog::new(cid, eid, "health_check", 1, None, None);
    if let Err(e) = log_entry.write_entry() {
        log::warn!("AI audit log failed: {}", e);
    }

    let start = std::time::Instant::now();
    let result = run_cli(
        vec!["kb-bridge".to_string(), "health".to_string()],
        app_handle,
    )
    .await;
    let elapsed = start.elapsed().as_millis() as i64;

    match &result {
        Ok(r) => {
            let kb_ok = r.exit_code == 0;
            if let Err(e) = log_entry.update_result(
                if kb_ok { 1 } else { 0 },
                elapsed,
                kb_ok,
                !kb_ok,
                None,
            ) {
                log::warn!("AI audit log failed: {}", e);
            }
        }
        Err(_) => {
            if let Err(e) = log_entry.update_result(0, elapsed, false, true, None) {
                log::warn!("AI audit log failed: {}", e);
            }
        }
    }

    result
}

/// KB search — Tier 1, operation_type: kb_search.
/// Audit log entry is written BEFORE the inference call per AI_AUDIT_TRAIL.md §7.1.
#[tauri::command]
async fn search_kb_bridge(
    query: String,
    case_id: Option<String>,
    examiner_id: Option<String>,
    app_handle: tauri::AppHandle,
) -> Result<CliRunResult, String> {
    let cid = case_id.as_deref().unwrap_or("NO_CASE");
    let eid = examiner_id.as_deref().unwrap_or("DEFAULT_UNSET");

    // Write audit entry BEFORE inference
    let mut log_entry = AiInteractionLog::new(
        cid,
        eid,
        "kb_search",
        1,
        Some(query.clone()),
        None,
    );
    if let Err(e) = log_entry.write_entry() {
        log::warn!("AI audit log failed: {}", e);
    }

    let start = std::time::Instant::now();
    let result = run_cli(
        vec![
            "kb-bridge".to_string(),
            "search".to_string(),
            "--query".to_string(),
            query,
        ],
        app_handle,
    )
    .await;
    let elapsed = start.elapsed().as_millis() as i64;

    match &result {
        Ok(r) => {
            let kb_ok = r.exit_code == 0;
            // Extract result_count and source_documents from envelope if available
            let (count, docs) = if let Some(ref env) = r.envelope_json {
                let count = env
                    .data
                    .as_ref()
                    .and_then(|d| d.get("result_count"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let docs = env
                    .data
                    .as_ref()
                    .and_then(|d| d.get("source_documents"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    });
                (count, docs)
            } else {
                (0, None)
            };

            if let Err(e) = log_entry.update_result(count, elapsed, kb_ok, !kb_ok, docs) {
                log::warn!("AI audit log failed: {}", e);
            }
        }
        Err(_) => {
            if let Err(e) = log_entry.update_result(0, elapsed, false, true, None) {
                log::warn!("AI audit log failed: {}", e);
            }
        }
    }

    result
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            if let Ok(app_data_dir) = app.path().app_data_dir() {
                if let Err(e) = std::fs::create_dir_all(&app_data_dir) {
                    log::warn!("Failed to create app data dir '{}': {}", app_data_dir.display(), e);
                } else {
                    let history_dir = app_data_dir.join("gui").join("runs");
                    if let Err(e) = std::fs::create_dir_all(&history_dir) {
                        log::warn!(
                            "Failed to create history dir '{}': {}",
                            history_dir.display(),
                            e
                        );
                    }
                }
            } else {
                log::warn!("Unable to resolve app data dir during startup");
            }

            log::info!("Forensic Suite GUI starting...");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![run_cli, get_cli_path, kb_bridge_health, search_kb_bridge])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}




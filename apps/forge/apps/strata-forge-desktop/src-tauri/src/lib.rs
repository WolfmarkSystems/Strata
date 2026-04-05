// ─── Module declarations ─────────────────────────────────────────
pub mod commands;
pub mod context;
pub mod context_server;
pub mod error;
pub mod export;
pub mod forge_state;
pub mod history;
pub mod ioc;
pub mod knowledge;
pub mod llm;
pub mod prompt;
pub mod settings;

// ─── Existing service management (preserved) ────────────────────
use futures_util::StreamExt;
use reqwest::header::CONTENT_TYPE;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use tauri::Emitter;

static WATCHDOG_ENABLED: AtomicBool = AtomicBool::new(true);
static DESIRED_OLLAMA: AtomicBool = AtomicBool::new(false);
static DESIRED_KB: AtomicBool = AtomicBool::new(false);

/// Thread-safe current folder state (replaces unsafe static mut).
static CURRENT_FOLDER: std::sync::LazyLock<Mutex<String>> =
    std::sync::LazyLock::new(|| Mutex::new(String::new()));

#[derive(Debug, Serialize)]
pub struct ServiceStatus {
    pub name: &'static str,
    pub process_running: bool,
    pub port_open: bool,
    pub port: u16,
    pub pid: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AllStatus {
    pub ollama: ServiceStatus,
    pub kb: ServiceStatus,
}

fn strata_root() -> PathBuf {
    std::env::var_os("STRATA_SUITE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\Strata"))
}

fn scripts_dir() -> PathBuf {
    strata_root().join("apps").join("forge").join("scripts")
}

fn ensure_exists(path: &Path) -> Result<(), String> {
    if path.exists() {
        Ok(())
    } else {
        Err(format!("Missing required file: {}", path.display()))
    }
}

fn tcp_port_open(port: u16) -> bool {
    for host in ["127.0.0.1", "localhost"] {
        let addr: Option<SocketAddr> = (host, port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next());

        if let Some(addr) = addr {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(350)).is_ok() {
                return true;
            }
        }
    }
    false
}

fn find_process_by_name(exe_name: &str) -> (bool, Option<u32>) {
    let refresh = RefreshKind::new().with_processes(ProcessRefreshKind::new());
    let mut sys = System::new_with_specifics(refresh);
    sys.refresh_processes();

    for (pid, proc_) in sys.processes() {
        let name: &str = proc_.name();
        if name.eq_ignore_ascii_case(exe_name) {
            return (true, Some(pid.as_u32()));
        }
    }
    (false, None)
}

fn find_any_python_pid() -> (bool, Option<u32>) {
    for candidate in ["python3.13.exe", "python.exe", "pythonw.exe", "py.exe"] {
        let (ok, pid) = find_process_by_name(candidate);
        if ok {
            return (true, pid);
        }
    }
    (false, None)
}

fn run_bat(bat_name: &str) -> Result<(), String> {
    let bat = scripts_dir().join(bat_name);
    ensure_exists(&bat)?;

    let status = Command::new("cmd.exe")
        .args(["/C", bat.to_string_lossy().as_ref()])
        .status()
        .map_err(|e| format!("Failed to run {}: {}", bat.display(), e))?;

    if !status.success() {
        return Err(format!(
            "Script failed (exit {:?}): {}",
            status.code(),
            bat.display()
        ));
    }

    Ok(())
}

#[tauri::command]
fn get_current_folder() -> String {
    CURRENT_FOLDER.lock().map(|g| g.clone()).unwrap_or_default()
}

#[tauri::command]
fn set_current_folder(path: String) -> String {
    if let Ok(mut guard) = CURRENT_FOLDER.lock() {
        *guard = path.clone();
    }
    path
}

#[tauri::command]
fn open_folder_in_explorer(path: String) -> String {
    match open::that(&path) {
        Ok(_) => "OK".to_string(),
        Err(e) => e.to_string(),
    }
}

#[tauri::command]
async fn select_folder(app: tauri::AppHandle) -> Result<String, String> {
    use tauri_plugin_dialog::DialogExt;

    let folder = app
        .dialog()
        .file()
        .set_title("Select Workspace Folder")
        .blocking_pick_folder();

    match folder {
        Some(path) => Ok(path.to_string()),
        None => Err("No folder selected".to_string()),
    }
}

#[tauri::command]
fn list_directory(path: String) -> Result<Vec<HashMap<String, String>>, String> {
    let mut entries = Vec::new();

    let read_dir = fs::read_dir(&path).map_err(|e| e.to_string())?;

    for entry in read_dir {
        let entry = entry.map_err(|e| e.to_string())?;
        let metadata = entry.metadata().map_err(|e| e.to_string())?;
        let file_name = entry.file_name().to_string_lossy().to_string();

        let mut item = HashMap::new();
        item.insert("name".to_string(), file_name);
        item.insert("is_dir".to_string(), metadata.is_dir().to_string());

        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                item.insert("modified".to_string(), duration.as_secs().to_string());
            }
        }

        item.insert("size".to_string(), metadata.len().to_string());

        entries.push(item);
    }

    let false_str = "false".to_string();
    let empty_str = String::new();

    entries.sort_by(|a, b| {
        let a_is_dir = a.get("is_dir").unwrap_or(&false_str) == "true";
        let b_is_dir = b.get("is_dir").unwrap_or(&false_str) == "true";

        match (a_is_dir, b_is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a
                .get("name")
                .unwrap_or(&empty_str)
                .to_lowercase()
                .cmp(&b.get("name").unwrap_or(&empty_str).to_lowercase()),
        }
    });

    Ok(entries)
}

#[tauri::command]
fn read_file(path: String) -> Result<String, String> {
    fs::read_to_string(&path).map_err(|e| e.to_string())
}

#[tauri::command]
fn write_file(path: String, content: String) -> Result<String, String> {
    fs::write(&path, &content).map_err(|e| e.to_string())?;
    Ok(format!("File written: {}", path))
}

#[tauri::command]
fn create_directory(path: String) -> Result<String, String> {
    fs::create_dir_all(&path).map_err(|e| e.to_string())?;
    Ok(format!("Directory created: {}", path))
}

#[tauri::command]
fn delete_path(path: String) -> Result<String, String> {
    let p = PathBuf::from(&path);
    if p.is_dir() {
        fs::remove_dir_all(&path).map_err(|e| e.to_string())?;
    } else {
        fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(format!("Deleted: {}", path))
}

/// Legacy streaming chat (kept for backward compatibility with existing UI).
#[tauri::command]
async fn start_stream_chat(
    window: tauri::Window,
    messages: Vec<HashMap<String, String>>,
    temperature: f32,
) -> Result<(), String> {
    let client = reqwest::Client::new();
    let kb_url = "http://127.0.0.1:8090";
    let ollama_url = "http://127.0.0.1:11434/v1/chat/completions";

    // 1. Get Context from KB Bridge
    let mut context_injected = String::new();
    if let Some(last_user) = messages
        .iter()
        .rev()
        .find(|m| m.get("role") == Some(&"user".to_string()))
    {
        let query = last_user.get("content").cloned().unwrap_or_default();
        if query.len() > 12 {
            let search_req = client
                .post(format!("{}/search", kb_url))
                .json(&serde_json::json!({ "query": query, "limit": 4 }))
                .timeout(Duration::from_millis(1500))
                .send()
                .await;

            if let Ok(resp) = search_req {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if let Some(results) = data.get("results").and_then(|r| r.as_array()) {
                        for res in results {
                            context_injected.push_str(&format!(
                                "\n[SOURCE] {}\n[FILE] {}\n{}\n",
                                res.get("source").and_then(|s| s.as_str()).unwrap_or("?"),
                                res.get("path").and_then(|p| p.as_str()).unwrap_or("?"),
                                res.get("snippet").and_then(|s| s.as_str()).unwrap_or("")
                            ));
                        }
                    }
                }
            }
        }
    }

    // 2. Prepare Payload
    let mut final_messages = messages.clone();
    if !context_injected.is_empty() {
        final_messages.insert(
            0,
            [
                ("role".to_string(), "system".to_string()),
                (
                    "content".to_string(),
                    format!("KNOWLEDGE CONTEXT:\n{}", context_injected),
                ),
            ]
            .into_iter()
            .collect(),
        );
    }

    let payload = serde_json::json!({
        "model": "phi4-mini",
        "messages": final_messages,
        "temperature": temperature,
        "stream": true
    });

    // 3. Stream from Ollama
    let mut stream = client
        .post(ollama_url)
        .header(CONTENT_TYPE, "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Ollama connection failed: {}", e))?
        .bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&chunk);

        for line in text.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                if data == "[DONE]" {
                    break;
                }
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(token) = val["choices"][0]["delta"]["content"].as_str() {
                        let _ = window.emit("chat-token", token);
                    }
                }
            }
        }
    }

    let _ = window.emit("chat-done", true);
    Ok(())
}

#[tauri::command]
fn status_all() -> AllStatus {
    let ollama_port = 11434;
    let (ollama_running, ollama_pid) = find_process_by_name("ollama.exe");

    let kb_port = 8090;
    let (kb_running, kb_pid) = find_any_python_pid();

    AllStatus {
        ollama: ServiceStatus {
            name: "ollama",
            process_running: ollama_running,
            port_open: tcp_port_open(ollama_port),
            port: ollama_port,
            pid: ollama_pid,
        },
        kb: ServiceStatus {
            name: "strata-kb-bridge",
            process_running: kb_running,
            port_open: tcp_port_open(kb_port),
            port: kb_port,
            pid: kb_pid,
        },
    }
}

#[tauri::command]
fn start_all() -> Result<(), String> {
    DESIRED_OLLAMA.store(true, Ordering::SeqCst);
    DESIRED_KB.store(true, Ordering::SeqCst);
    start_ollama()?;
    start_kb()?;
    Ok(())
}

#[tauri::command]
fn stop_all() -> Result<(), String> {
    DESIRED_OLLAMA.store(false, Ordering::SeqCst);
    DESIRED_KB.store(false, Ordering::SeqCst);
    stop_kb()?;
    stop_ollama()?;
    Ok(())
}

#[tauri::command]
fn restart_all() -> Result<(), String> {
    restart_ollama()?;
    restart_kb()?;
    Ok(())
}

#[tauri::command]
fn start_ollama() -> Result<(), String> {
    DESIRED_OLLAMA.store(true, Ordering::SeqCst);
    run_bat("start_ollama.bat")
}

#[tauri::command]
fn stop_ollama() -> Result<(), String> {
    DESIRED_OLLAMA.store(false, Ordering::SeqCst);
    run_bat("stop_ollama.bat")
}

#[tauri::command]
fn restart_ollama() -> Result<(), String> {
    run_bat("restart_strata_forge.bat")
}

#[tauri::command]
fn start_kb() -> Result<(), String> {
    DESIRED_KB.store(true, Ordering::SeqCst);
    run_bat("start_kb_bridge.bat")
}

#[tauri::command]
fn stop_kb() -> Result<(), String> {
    DESIRED_KB.store(false, Ordering::SeqCst);
    run_bat("stop_kb_bridge.bat")
}

#[tauri::command]
fn restart_kb() -> Result<(), String> {
    run_bat("restart_kb_bridge.bat")
}

#[tauri::command]
fn open_dfir_chat() -> Result<(), String> {
    let url = "http://127.0.0.1:11434";
    Command::new("cmd.exe")
        .args(["/C", "start", "", url])
        .status()
        .map_err(|e| format!("Failed to open browser: {}", e))?;
    Ok(())
}

#[tauri::command]
fn open_kb_ui() -> Result<(), String> {
    let url = "http://127.0.0.1:8090";
    Command::new("cmd.exe")
        .args(["/C", "start", "", url])
        .status()
        .map_err(|e| format!("Failed to open browser: {}", e))?;
    Ok(())
}

#[tauri::command]
fn toggle_watchdog(enable: bool) {
    WATCHDOG_ENABLED.store(enable, Ordering::SeqCst);
}

// ─── Application entry point ─────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Load settings (or defaults if first run)
    let forge_settings = settings::ForgeSettings::load();
    let ctx_port = forge_settings.context_server_port;

    // Initialize ForgeState with settings-driven config
    let forge_state = forge_state::ForgeState::new(forge_settings);

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(forge_state)
        .invoke_handler(tauri::generate_handler![
            // ── Legacy service management ──
            status_all,
            toggle_watchdog,
            start_ollama,
            stop_ollama,
            restart_ollama,
            start_kb,
            stop_kb,
            restart_kb,
            start_all,
            stop_all,
            restart_all,
            open_dfir_chat,
            open_kb_ui,
            // ── Legacy workspace/file ops ──
            get_current_folder,
            set_current_folder,
            open_folder_in_explorer,
            select_folder,
            list_directory,
            read_file,
            write_file,
            create_directory,
            delete_path,
            start_stream_chat,
            // ── Forge LLM commands ──
            commands::forge_query,
            commands::forge_stream_query,
            commands::forge_health_check,
            commands::forge_list_models,
            commands::forge_set_llm_config,
            // ── Context commands ──
            commands::forge_set_context,
            commands::forge_get_context,
            commands::forge_clear_context,
            // ── Quick tool commands ──
            commands::forge_explain,
            commands::forge_ioc_lookup,
            commands::forge_attack_map,
            commands::forge_draft_paragraph,
            commands::forge_synthesize_timeline,
            // ── IOC enrichment ──
            commands::forge_enrich_ioc,
            commands::forge_classify_ioc,
            commands::forge_kb_stats,
            // ── Settings commands ──
            commands::forge_get_settings,
            commands::forge_save_settings,
            commands::forge_is_first_run,
            // ── History commands ──
            commands::forge_list_conversations,
            commands::forge_load_conversation,
            commands::forge_save_conversation,
            commands::forge_delete_conversation,
            commands::forge_new_conversation,
            // ── Export commands ──
            commands::forge_export_text,
            commands::forge_export_markdown,
            commands::forge_export_html,
        ])
        .setup(move |_app| {
            // Start the Tree integration context server
            if let Err(e) = context_server::start_context_server(ctx_port) {
                eprintln!("[FORGE] Context server failed to start: {}", e);
            }

            // Start the Watchdog thread
            thread::spawn(move || loop {
                thread::sleep(Duration::from_secs(10));

                if !WATCHDOG_ENABLED.load(Ordering::SeqCst) {
                    continue;
                }

                if DESIRED_OLLAMA.load(Ordering::SeqCst) {
                    let (running, _) = find_process_by_name("ollama.exe");
                    if !running {
                        println!("[WATCHDOG] OLLAMA down. Restarting...");
                        let _ = run_bat("start_ollama.bat");
                    }
                }

                if DESIRED_KB.load(Ordering::SeqCst) {
                    let (running, _) = find_any_python_pid();
                    if !running {
                        println!("[WATCHDOG] KB Bridge down. Restarting...");
                        let _ = run_bat("start_kb_bridge.bat");
                    }
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

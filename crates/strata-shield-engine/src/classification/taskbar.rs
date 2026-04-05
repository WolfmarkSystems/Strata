use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct TaskbarEntry {
    pub app_id: String,
    pub display_name: String,
    pub exe_path: String,
    pub arguments: String,
    pub icon_path: String,
    pub pin_status: PinStatus,
    pub last_accessed: Option<u64>,
    pub launch_count: u32,
}

#[derive(Debug, Clone, Default)]
pub enum PinStatus {
    #[default]
    Unknown,
    Pinned,
    Unpinned,
    Recent,
}

#[derive(Debug, Clone, Default)]
pub struct StartMenuEntry {
    pub name: String,
    pub path: String,
    pub target_path: String,
    pub arguments: String,
    pub icon_location: String,
    pub working_directory: String,
    pub entry_type: StartMenuEntryType,
    pub last_modified: Option<u64>,
    pub created: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub enum StartMenuEntryType {
    #[default]
    Application,
    Folder,
    Link,
    Shortcut,
    ControlPanel,
    Settings,
    Document,
}

#[derive(Debug, Clone, Default)]
pub struct TaskbarPinHistory {
    pub entries: Vec<TaskbarPinAction>,
}

#[derive(Debug, Clone, Default)]
pub struct TaskbarPinAction {
    pub app_id: String,
    pub action: PinAction,
    pub timestamp: u64,
    pub user: String,
}

#[derive(Debug, Clone, Default)]
pub enum PinAction {
    #[default]
    Unknown,
    Pin,
    Unpin,
    Reorder,
}

pub fn get_start_menu_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs"),
        PathBuf::from(r"C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"),
    ]
}

pub fn get_taskbar_data_path() -> PathBuf {
    PathBuf::from(r"C:\Users\AppData\Local\Microsoft\Windows\Taskbar")
}

pub fn scan_start_menu(user_profile: &Path) -> Result<Vec<StartMenuEntry>, ForensicError> {
    let mut entries = vec![];

    let start_menu_path =
        user_profile.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs");

    if start_menu_path.exists() {
        entries.push(StartMenuEntry {
            name: "".to_string(),
            path: start_menu_path.to_string_lossy().to_string(),
            target_path: "".to_string(),
            arguments: "".to_string(),
            icon_location: "".to_string(),
            working_directory: "".to_string(),
            entry_type: StartMenuEntryType::Folder,
            last_modified: None,
            created: None,
        });
    }

    Ok(entries)
}

pub fn parse_taskbar_pin_history(path: &Path) -> Result<TaskbarPinHistory, ForensicError> {
    let mut history = TaskbarPinHistory::default();

    if path.exists() {
        history.entries.push(TaskbarPinAction {
            app_id: "".to_string(),
            action: PinAction::Unknown,
            timestamp: 0,
            user: "".to_string(),
        });
    }

    Ok(history)
}

pub fn get_recent_apps() -> Result<Vec<TaskbarEntry>, ForensicError> {
    get_taskbar_entries("FORENSIC_TASKBAR_RECENT_APPS", "taskbar_recent_apps.json")
}

pub fn get_pinned_apps() -> Result<Vec<TaskbarEntry>, ForensicError> {
    get_taskbar_entries("FORENSIC_TASKBAR_PINNED_APPS", "taskbar_pinned_apps.json")
}

pub fn get_taskbar_jumplist_entries() -> Result<Vec<TaskbarEntry>, ForensicError> {
    get_taskbar_entries(
        "FORENSIC_TASKBAR_JUMPLIST_ENTRIES",
        "taskbar_jumplist_entries.json",
    )
}

pub fn scan_all_start_menu() -> Result<Vec<StartMenuEntry>, ForensicError> {
    let all_entries = vec![];
    Ok(all_entries)
}

pub fn extract_taskbar_aggregation() -> Result<HashMap<String, u32>, ForensicError> {
    let mut aggregation = HashMap::new();
    aggregation.insert("total_pinned".to_string(), 0);
    aggregation.insert("total_recent".to_string(), 0);
    aggregation.insert("launch_count_total".to_string(), 0);
    Ok(aggregation)
}

fn get_taskbar_entries(env_key: &str, file: &str) -> Result<Vec<TaskbarEntry>, ForensicError> {
    let Some(items) = load(path(env_key, file)) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| TaskbarEntry {
            app_id: s(&v, &["app_id", "id"]),
            display_name: s(&v, &["display_name", "name"]),
            exe_path: s(&v, &["exe_path", "path"]),
            arguments: s(&v, &["arguments"]),
            icon_path: s(&v, &["icon_path", "icon"]),
            pin_status: pin_status_enum(s(&v, &["pin_status", "status"])),
            last_accessed: opt_n(&v, &["last_accessed", "timestamp"]),
            launch_count: n(&v, &["launch_count", "count"]) as u32,
        })
        .filter(|x| !x.app_id.is_empty() || !x.display_name.is_empty() || !x.exe_path.is_empty())
        .collect())
}

fn pin_status_enum(value: String) -> PinStatus {
    match value.to_ascii_lowercase().as_str() {
        "pinned" => PinStatus::Pinned,
        "unpinned" => PinStatus::Unpinned,
        "recent" => PinStatus::Recent,
        _ => PinStatus::Unknown,
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("taskbar").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let v: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = v.as_array() {
        Some(items.clone())
    } else if v.is_object() {
        v.get("items")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| v.get("results").and_then(Value::as_array).cloned())
            .or_else(|| Some(vec![v]))
    } else {
        None
    }
}

fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}

fn n(v: &Value, keys: &[&str]) -> u64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return x as u64;
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return n;
            }
        }
    }
    0
}

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return Some(x as u64);
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

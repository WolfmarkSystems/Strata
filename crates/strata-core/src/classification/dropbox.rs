use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct DropboxSyncState {
    pub account_email: String,
    pub sync_folder: String,
    pub host_id: String,
    pub last_sync: Option<u64>,
    pub synced_files: Vec<DropboxFile>,
}

#[derive(Debug, Clone, Default)]
pub struct DropboxFile {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub modified: Option<u64>,
    pub sync_rev: String,
    pub is_deleted: bool,
    pub is_folder: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DropboxEvent {
    pub timestamp: u64,
    pub event_type: DropboxEventType,
    pub path: String,
    pub details: String,
}

#[derive(Debug, Clone, Default)]
pub enum DropboxEventType {
    #[default]
    Unknown,
    FileUpload,
    FileDelete,
    FileMove,
    FileRename,
    FolderCreate,
    FolderDelete,
    Login,
    Logout,
}

pub fn get_dropbox_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\Users\Default\AppData\Roaming\Dropbox"),
        PathBuf::from(r"C:\Users\Default\AppData\Local\Dropbox"),
        PathBuf::from(r"C:\Program Files (x86)\Dropbox"),
    ]
}

pub fn get_dropbox_config_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Default\AppData\Roaming\Dropbox\config")
}

pub fn get_dropbox_info_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Default\AppData\Roaming\Dropbox\info.json")
}

pub fn parse_dropbox_config(config_path: &Path) -> Result<DropboxConfig, ForensicError> {
    let Some(v) = load_value(config_path) else {
        return Ok(DropboxConfig {
            account_email: String::new(),
            sync_folder: String::new(),
            host_id: String::new(),
        });
    };
    Ok(DropboxConfig {
        account_email: s(&v, &["account_email", "email"]),
        sync_folder: s(&v, &["sync_folder", "path"]),
        host_id: s(&v, &["host_id"]),
    })
}

#[derive(Debug, Clone, Default)]
pub struct DropboxConfig {
    pub account_email: String,
    pub sync_folder: String,
    pub host_id: String,
}

pub fn get_dropbox_db_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Default\AppData\Roaming\Dropbox\dropbox.db")
}

pub fn parse_dropbox_database(db_path: &Path) -> Result<DropboxSyncState, ForensicError> {
    let Some(v) = load_value(db_path) else {
        return Ok(DropboxSyncState {
            account_email: String::new(),
            sync_folder: String::new(),
            host_id: String::new(),
            last_sync: None,
            synced_files: Vec::new(),
        });
    };
    let synced_files = v
        .get("synced_files")
        .and_then(Value::as_array)
        .map(|xs| xs.iter().map(parse_dropbox_file).collect())
        .unwrap_or_default();
    Ok(DropboxSyncState {
        account_email: s(&v, &["account_email", "email"]),
        sync_folder: s(&v, &["sync_folder", "path"]),
        host_id: s(&v, &["host_id"]),
        last_sync: opt_n(&v, &["last_sync", "timestamp"]),
        synced_files,
    })
}

pub fn get_dropbox_log_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Default\AppData\Local\Dropbox\logs")
}

pub fn get_dropbox_history() -> Result<Vec<DropboxEvent>, ForensicError> {
    let Some(items) = load(path("FORENSIC_DROPBOX_HISTORY", "dropbox_history.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| DropboxEvent {
            timestamp: n(&v, &["timestamp", "time"]),
            event_type: event_type_enum(s(&v, &["event_type", "type"])),
            path: s(&v, &["path"]),
            details: s(&v, &["details", "message"]),
        })
        .filter(|x| x.timestamp > 0 || !x.path.is_empty())
        .collect())
}

pub fn detect_dropbox_install() -> bool {
    let paths = get_dropbox_paths();
    paths.iter().any(|p| p.exists())
}

pub fn get_dropbox_selective_sync() -> Result<Vec<String>, ForensicError> {
    let Some(v) = load_value(&path(
        "FORENSIC_DROPBOX_SELECTIVE_SYNC",
        "dropbox_selective_sync.json",
    )) else {
        return Ok(Vec::new());
    };
    if let Some(items) = v.as_array() {
        return Ok(items
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect());
    }
    if let Some(items) = v.get("paths").and_then(Value::as_array) {
        return Ok(items
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect());
    }
    Ok(Vec::new())
}

pub fn get_dropbox_camera_upload() -> Result<DropboxCameraUpload, ForensicError> {
    let Some(v) = load_value(&path(
        "FORENSIC_DROPBOX_CAMERA_UPLOAD",
        "dropbox_camera_upload.json",
    )) else {
        return Ok(DropboxCameraUpload {
            enabled: false,
            folder: String::new(),
            last_upload: None,
        });
    };
    Ok(DropboxCameraUpload {
        enabled: b(&v, &["enabled"]),
        folder: s(&v, &["folder", "path"]),
        last_upload: opt_n(&v, &["last_upload", "timestamp"]),
    })
}

#[derive(Debug, Clone, Default)]
pub struct DropboxCameraUpload {
    pub enabled: bool,
    pub folder: String,
    pub last_upload: Option<u64>,
}

pub fn get_dropbox_team_folders() -> Result<Vec<DropboxTeamFolder>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_DROPBOX_TEAM_FOLDERS",
        "dropbox_team_folders.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| DropboxTeamFolder {
            name: s(&v, &["name"]),
            shared: b(&v, &["shared", "is_shared"]),
            sync_enabled: b(&v, &["sync_enabled", "is_synced"]),
        })
        .filter(|x| !x.name.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct DropboxTeamFolder {
    pub name: String,
    pub shared: bool,
    pub sync_enabled: bool,
}

fn parse_dropbox_file(v: &Value) -> DropboxFile {
    DropboxFile {
        path: s(v, &["path"]),
        name: s(v, &["name"]),
        size: n(v, &["size", "size_bytes"]),
        modified: opt_n(v, &["modified", "modified_time"]),
        sync_rev: s(v, &["sync_rev", "rev"]),
        is_deleted: b(v, &["is_deleted", "deleted"]),
        is_folder: b(v, &["is_folder", "folder"]),
    }
}

fn event_type_enum(value: String) -> DropboxEventType {
    match value.to_ascii_lowercase().as_str() {
        "fileupload" | "file_upload" => DropboxEventType::FileUpload,
        "filedelete" | "file_delete" => DropboxEventType::FileDelete,
        "filemove" | "file_move" => DropboxEventType::FileMove,
        "filerename" | "file_rename" => DropboxEventType::FileRename,
        "foldercreate" | "folder_create" => DropboxEventType::FolderCreate,
        "folderdelete" | "folder_delete" => DropboxEventType::FolderDelete,
        "login" => DropboxEventType::Login,
        "logout" => DropboxEventType::Logout,
        _ => DropboxEventType::Unknown,
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key).map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from("artifacts")
            .join("cloud")
            .join("dropbox")
            .join(file)
    })
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let v = load_value(&path)?;
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

fn load_value(path: &Path) -> Option<Value> {
    let data = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data).ok()
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
    opt_n(v, keys).unwrap_or(0)
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

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}

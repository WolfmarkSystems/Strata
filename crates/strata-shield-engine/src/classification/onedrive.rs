use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct OneDriveSyncState {
    pub account_email: String,
    pub sync_folder: String,
    pub sync_enabled: bool,
    pub last_sync: Option<u64>,
    pub synced_files: Vec<OneDriveFile>,
}

#[derive(Debug, Clone, Default)]
pub struct OneDriveFile {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub local_modified: Option<u64>,
    pub remote_modified: Option<u64>,
    pub sync_status: SyncStatus,
    pub etag: String,
    pub ctag: String,
}

#[derive(Debug, Clone, Default)]
pub enum SyncStatus {
    #[default]
    Unknown,
    Synced,
    Pending,
    Uploading,
    Downloading,
    Conflict,
    Error,
    Excluded,
}

#[derive(Debug, Clone, Default)]
pub struct OneDriveVersion {
    pub file_path: String,
    pub version_id: String,
    pub modified_time: u64,
    pub modified_by: String,
    pub size: u64,
}

pub fn get_onedrive_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\Users\Default\AppData\Local\Microsoft\OneDrive"),
        PathBuf::from(r"C:\Program Files\Microsoft OneDrive"),
        PathBuf::from(r"C:\Program Files (x86)\Microsoft OneDrive"),
    ]
}

pub fn get_onedrive_settings_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Default\AppData\Local\Microsoft\OneDrive\settings")
}

pub fn parse_onedrive_config(config_path: &Path) -> Result<HashMap<String, String>, ForensicError> {
    let v = load_value(config_path);
    let mut config = HashMap::new();
    config.insert(
        "account_email".to_string(),
        v.as_ref()
            .map(|x| s(x, &["account_email", "email"]))
            .unwrap_or_default(),
    );
    config.insert(
        "sync_folder".to_string(),
        v.as_ref()
            .map(|x| s(x, &["sync_folder", "path"]))
            .unwrap_or_default(),
    );
    config.insert(
        "machine_id".to_string(),
        v.as_ref()
            .map(|x| s(x, &["machine_id", "host_id"]))
            .unwrap_or_default(),
    );
    Ok(config)
}

pub fn scan_onedrive_sync_db(db_path: &Path) -> Result<OneDriveSyncState, ForensicError> {
    let Some(v) = load_value(db_path) else {
        return Ok(OneDriveSyncState {
            account_email: String::new(),
            sync_folder: String::new(),
            sync_enabled: false,
            last_sync: None,
            synced_files: Vec::new(),
        });
    };
    let synced_files = v
        .get("synced_files")
        .and_then(Value::as_array)
        .map(|xs| {
            xs.iter()
                .map(|x| OneDriveFile {
                    path: s(x, &["path"]),
                    name: s(x, &["name"]),
                    size: n(x, &["size", "size_bytes"]),
                    local_modified: opt_n(x, &["local_modified", "local_modified_time"]),
                    remote_modified: opt_n(x, &["remote_modified", "remote_modified_time"]),
                    sync_status: sync_status_enum(s(x, &["sync_status", "status"])),
                    etag: s(x, &["etag"]),
                    ctag: s(x, &["ctag"]),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(OneDriveSyncState {
        account_email: s(&v, &["account_email", "email"]),
        sync_folder: s(&v, &["sync_folder", "path"]),
        sync_enabled: b(&v, &["sync_enabled", "enabled"]),
        last_sync: opt_n(&v, &["last_sync", "timestamp"]),
        synced_files,
    })
}

pub fn get_onedrive_log_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Default\AppData\Local\Microsoft\OneDrive\logs")
}

pub fn parse_onedrive_log(log_path: &Path) -> Result<Vec<OneDriveLogEntry>, ForensicError> {
    let Some(items) = load(log_path) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| OneDriveLogEntry {
            timestamp: n(&v, &["timestamp", "time"]),
            level: s(&v, &["level"]),
            message: s(&v, &["message"]),
            file_path: s_opt(&v, &["file_path", "path"]),
        })
        .filter(|x| x.timestamp > 0 || !x.message.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct OneDriveLogEntry {
    pub timestamp: u64,
    pub level: String,
    pub message: String,
    pub file_path: Option<String>,
}

pub fn get_onedrive_versions(file_path: &str) -> Result<Vec<OneDriveVersion>, ForensicError> {
    let path = env::var("FORENSIC_ONEDRIVE_VERSIONS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("cloud")
                .join("onedrive")
                .join("onedrive_versions.json")
        });
    let Some(items) = load(&path) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| OneDriveVersion {
            file_path: s(&v, &["file_path", "path"]),
            version_id: s(&v, &["version_id", "id"]),
            modified_time: n(&v, &["modified_time", "timestamp"]),
            modified_by: s(&v, &["modified_by", "actor"]),
            size: n(&v, &["size", "size_bytes"]),
        })
        .filter(|x| x.file_path == file_path || file_path.is_empty())
        .collect())
}

pub fn detect_onedrive_install() -> bool {
    let paths = get_onedrive_paths();
    paths.iter().any(|p| p.exists())
}

pub fn get_onedrive_share_links() -> Result<Vec<OneDriveShareLink>, ForensicError> {
    let Some(items) = load(&path(
        "FORENSIC_ONEDRIVE_SHARE_LINKS",
        "onedrive_share_links.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| OneDriveShareLink {
            link: s(&v, &["link", "url"]),
            file_path: s(&v, &["file_path", "path"]),
            created_time: n(&v, &["created_time", "timestamp"]),
            expires_time: opt_n(&v, &["expires_time", "expiration_time"]),
            permissions: s(&v, &["permissions", "scope"]),
        })
        .filter(|x| !x.link.is_empty() || !x.file_path.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct OneDriveShareLink {
    pub link: String,
    pub file_path: String,
    pub created_time: u64,
    pub expires_time: Option<u64>,
    pub permissions: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key).map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from("artifacts")
            .join("cloud")
            .join("onedrive")
            .join(file)
    })
}

fn load(path: &Path) -> Option<Vec<Value>> {
    let v = load_value(path)?;
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

fn s_opt(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return Some(x.to_string());
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

fn sync_status_enum(value: String) -> SyncStatus {
    match value.to_ascii_lowercase().as_str() {
        "synced" => SyncStatus::Synced,
        "pending" => SyncStatus::Pending,
        "uploading" => SyncStatus::Uploading,
        "downloading" => SyncStatus::Downloading,
        "conflict" => SyncStatus::Conflict,
        "error" => SyncStatus::Error,
        "excluded" => SyncStatus::Excluded,
        _ => SyncStatus::Unknown,
    }
}

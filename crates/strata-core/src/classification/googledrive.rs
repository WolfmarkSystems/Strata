use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct GoogleDriveSyncState {
    pub account_email: String,
    pub sync_folder: String,
    pub is_team_drive: bool,
    pub last_sync: Option<u64>,
    pub synced_files: Vec<GoogleDriveFile>,
}

#[derive(Debug, Clone, Default)]
pub struct GoogleDriveFile {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub modified: Option<u64>,
    pub mime_type: String,
    pub file_id: String,
    pub parents: Vec<String>,
    pub is_shared: bool,
    pub sha1_hash: String,
}

#[derive(Debug, Clone, Default)]
pub struct GoogleDriveSnapshot {
    pub snapshot_time: u64,
    pub account_email: String,
    pub files: Vec<GoogleDriveFile>,
}

#[derive(Debug, Clone, Default)]
pub struct GoogleDriveVersion {
    pub file_id: String,
    pub version_id: String,
    pub modified_time: u64,
    pub modified_by: String,
    pub size: u64,
}

pub fn get_google_drive_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\Users\Default\AppData\Local\Google\DriveFS"),
        PathBuf::from(r"C:\Program Files\Google\Drive File Stream"),
        PathBuf::from(r"C:\Program Files (x86)\Google\Drive File Stream"),
    ]
}

pub fn get_google_drive_config_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Default\AppData\Local\Google\DriveFS\content_cache")
}

pub fn get_google_drive_token_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Default\AppData\Local\Google\DriveFS\tokens")
}

pub fn parse_google_drive_config(config_path: &Path) -> Result<GoogleDriveConfig, ForensicError> {
    let Some(v) = load_value(config_path) else {
        return Ok(GoogleDriveConfig {
            account_email: String::new(),
            sync_folder: String::new(),
            is_team_drive: false,
        });
    };
    Ok(GoogleDriveConfig {
        account_email: s(&v, &["account_email", "email"]),
        sync_folder: s(&v, &["sync_folder", "root_path"]),
        is_team_drive: b(&v, &["is_team_drive", "team_drive"]),
    })
}

#[derive(Debug, Clone, Default)]
pub struct GoogleDriveConfig {
    pub account_email: String,
    pub sync_folder: String,
    pub is_team_drive: bool,
}

pub fn get_google_drive_db_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Default\AppData\Local\Google\DriveFS\snapshot.db")
}

pub fn parse_google_drive_snapshot(db_path: &Path) -> Result<GoogleDriveSnapshot, ForensicError> {
    let Some(v) = load_value(db_path) else {
        return Ok(GoogleDriveSnapshot {
            snapshot_time: 0,
            account_email: String::new(),
            files: Vec::new(),
        });
    };
    let files = if let Some(items) = v.get("files").and_then(Value::as_array) {
        items.iter().map(parse_drive_file).collect()
    } else if v.is_array() {
        v.as_array()
            .map(|items| items.iter().map(parse_drive_file).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Ok(GoogleDriveSnapshot {
        snapshot_time: n(&v, &["snapshot_time", "timestamp"]),
        account_email: s(&v, &["account_email", "email"]),
        files,
    })
}

pub fn get_google_drive_log_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Default\AppData\Local\Google\DriveFS\logs")
}

pub fn get_google_drive_metadata_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Default\AppData\Local\Google\DriveFS\content_cache\metadata_cache")
}

pub fn detect_google_drive_install() -> bool {
    let paths = get_google_drive_paths();
    paths.iter().any(|p| p.exists())
}

pub fn get_team_drive_info() -> Result<Vec<GoogleTeamDrive>, ForensicError> {
    let Some(items) = load(path("FORENSIC_GOOGLE_DRIVE_TEAM", "google_drive_team.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| GoogleTeamDrive {
            name: s(&v, &["name"]),
            id: s(&v, &["id", "team_drive_id"]),
            created_time: n(&v, &["created_time", "created"]),
            storage_quota: n(&v, &["storage_quota", "quota"]),
        })
        .filter(|x| !x.name.is_empty() || !x.id.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct GoogleTeamDrive {
    pub name: String,
    pub id: String,
    pub created_time: u64,
    pub storage_quota: u64,
}

pub fn get_shared_drive_files() -> Result<Vec<GoogleDriveFile>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_GOOGLE_DRIVE_SHARED_FILES",
        "google_drive_shared_files.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| parse_drive_file(&v))
        .filter(|x| !x.file_id.is_empty() || !x.path.is_empty())
        .collect())
}

pub fn get_google_drive_shortcuts() -> Result<Vec<GoogleDriveShortcut>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_GOOGLE_DRIVE_SHORTCUTS",
        "google_drive_shortcuts.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| GoogleDriveShortcut {
            shortcut_path: s(&v, &["shortcut_path", "path"]),
            target_file_id: s(&v, &["target_file_id", "file_id"]),
            target_name: s(&v, &["target_name", "name"]),
        })
        .filter(|x| !x.shortcut_path.is_empty() || !x.target_file_id.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct GoogleDriveShortcut {
    pub shortcut_path: String,
    pub target_file_id: String,
    pub target_name: String,
}

pub fn get_google_drive_offline_files() -> Result<Vec<String>, ForensicError> {
    let Some(v) = load_value(&path(
        "FORENSIC_GOOGLE_DRIVE_OFFLINE_FILES",
        "google_drive_offline_files.json",
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
    if let Some(items) = v.get("files").and_then(Value::as_array) {
        return Ok(items
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect());
    }
    Ok(Vec::new())
}

pub fn get_google_drive_updates() -> Result<Vec<GoogleDriveUpdate>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_GOOGLE_DRIVE_UPDATES",
        "google_drive_updates.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| GoogleDriveUpdate {
            timestamp: n(&v, &["timestamp", "time"]),
            file_id: s(&v, &["file_id", "id"]),
            file_name: s(&v, &["file_name", "name"]),
            update_type: s(&v, &["update_type", "type"]),
        })
        .filter(|x| x.timestamp > 0 || !x.file_id.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct GoogleDriveUpdate {
    pub timestamp: u64,
    pub file_id: String,
    pub file_name: String,
    pub update_type: String,
}

fn parse_drive_file(v: &Value) -> GoogleDriveFile {
    GoogleDriveFile {
        path: s(v, &["path"]),
        name: s(v, &["name"]),
        size: n(v, &["size", "size_bytes"]),
        modified: opt_n(v, &["modified", "modified_time"]),
        mime_type: s(v, &["mime_type", "mime"]),
        file_id: s(v, &["file_id", "id"]),
        parents: str_vec(v, &["parents"]),
        is_shared: b(v, &["is_shared", "shared"]),
        sha1_hash: s(v, &["sha1_hash", "hash"]),
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key).map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from("artifacts")
            .join("cloud")
            .join("google_drive")
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

fn str_vec(v: &Value, keys: &[&str]) -> Vec<String> {
    for k in keys {
        if let Some(items) = v.get(*k).and_then(Value::as_array) {
            return items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect();
        }
    }
    Vec::new()
}

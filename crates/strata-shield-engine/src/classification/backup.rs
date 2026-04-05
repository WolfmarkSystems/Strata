use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct WindowsBackup {
    pub backup_id: String,
    pub backup_type: BackupType,
    pub source_path: String,
    pub destination_path: String,
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub status: BackupStatus,
    pub size_bytes: u64,
    pub files_backed_up: u32,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub enum BackupType {
    #[default]
    Full,
    Incremental,
    Differential,
    SystemImage,
}

#[derive(Debug, Clone, Default)]
pub enum BackupStatus {
    #[default]
    Unknown,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

pub fn get_backup_history() -> Result<Vec<WindowsBackup>, ForensicError> {
    let Some(items) = load(path("FORENSIC_BACKUP_HISTORY", "backup_history.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(parse_windows_backup)
        .filter(|x| !x.backup_id.is_empty() || !x.source_path.is_empty())
        .collect())
}

pub fn get_system_image_backups() -> Result<Vec<WindowsBackup>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_SYSTEM_IMAGE_BACKUPS",
        "system_image_backups.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(parse_windows_backup)
        .filter(|x| !x.backup_id.is_empty() || matches!(x.backup_type, BackupType::SystemImage))
        .collect())
}

pub fn get_file_history() -> Result<Vec<FileHistoryEntry>, ForensicError> {
    let Some(items) = load(path("FORENSIC_FILE_HISTORY", "file_history.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| FileHistoryEntry {
            file_path: s(&v, &["file_path", "path"]),
            original_time: n(&v, &["original_time", "created_time"]),
            restored_time: opt_n(&v, &["restored_time"]),
            backup_time: n(&v, &["backup_time", "timestamp"]),
            size: n(&v, &["size", "size_bytes"]),
        })
        .filter(|x| !x.file_path.is_empty() || x.backup_time > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct FileHistoryEntry {
    pub file_path: String,
    pub original_time: u64,
    pub restored_time: Option<u64>,
    pub backup_time: u64,
    pub size: u64,
}

pub fn scan_backup_locations() -> Result<Vec<BackupLocation>, ForensicError> {
    let Some(items) = load(path("FORENSIC_BACKUP_LOCATIONS", "backup_locations.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| BackupLocation {
            path: s(&v, &["path"]),
            backup_type: s(&v, &["backup_type", "type"]),
            last_backup: opt_n(&v, &["last_backup", "last_backup_time"]),
            total_size: n(&v, &["total_size", "total_size_bytes"]),
            available_space: n(&v, &["available_space", "available_space_bytes"]),
        })
        .filter(|x| !x.path.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct BackupLocation {
    pub path: String,
    pub backup_type: String,
    pub last_backup: Option<u64>,
    pub total_size: u64,
    pub available_space: u64,
}

fn parse_windows_backup(v: Value) -> WindowsBackup {
    WindowsBackup {
        backup_id: s(&v, &["backup_id", "id"]),
        backup_type: backup_type_enum(s(&v, &["backup_type", "type"])),
        source_path: s(&v, &["source_path", "source"]),
        destination_path: s(&v, &["destination_path", "destination"]),
        start_time: opt_n(&v, &["start_time"]),
        end_time: opt_n(&v, &["end_time"]),
        status: backup_status_enum(s(&v, &["status"])),
        size_bytes: n(&v, &["size_bytes", "size"]),
        files_backed_up: n(&v, &["files_backed_up", "file_count"]) as u32,
        errors: str_vec(&v, &["errors"]),
    }
}

fn backup_type_enum(value: String) -> BackupType {
    match value.to_ascii_lowercase().as_str() {
        "incremental" => BackupType::Incremental,
        "differential" => BackupType::Differential,
        "systemimage" | "system_image" => BackupType::SystemImage,
        _ => BackupType::Full,
    }
}

fn backup_status_enum(value: String) -> BackupStatus {
    match value.to_ascii_lowercase().as_str() {
        "inprogress" | "in_progress" => BackupStatus::InProgress,
        "completed" | "complete" => BackupStatus::Completed,
        "failed" | "error" => BackupStatus::Failed,
        "cancelled" | "canceled" => BackupStatus::Cancelled,
        _ => BackupStatus::Unknown,
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("backup").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let json: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = json.as_array() {
        Some(items.clone())
    } else if json.is_object() {
        Some(vec![json])
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
        if let Some(xs) = v.get(*k).and_then(Value::as_array) {
            return xs
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect();
        }
    }
    Vec::new()
}

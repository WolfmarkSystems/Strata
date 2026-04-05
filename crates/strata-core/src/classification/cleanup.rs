use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct DiskCleanupItem {
    pub name: String,
    pub description: String,
    pub size_bytes: u64,
    pub category: CleanupCategory,
}

#[derive(Debug, Clone, Default)]
pub enum CleanupCategory {
    #[default]
    TemporaryFiles,
    SystemFiles,
    DownloadFiles,
    RecycleBin,
    WindowsUpdate,
    DeviceDriver,
    ErrorReports,
    WindowsUpgrade,
    OfflineWebPages,
}

pub fn get_disk_cleanup_items() -> Result<Vec<DiskCleanupItem>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_DISK_CLEANUP_ITEMS",
        "disk_cleanup_items.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| DiskCleanupItem {
            name: s(&v, &["name"]),
            description: s(&v, &["description"]),
            size_bytes: n(&v, &["size_bytes", "size"]),
            category: category_enum(s(&v, &["category"])),
        })
        .filter(|x| !x.name.is_empty() || x.size_bytes > 0)
        .collect())
}

pub fn get_temp_files_locations() -> Vec<TempLocation> {
    vec![
        TempLocation {
            path: r"C:\Windows\Temp".to_string(),
            user_specific: false,
        },
        TempLocation {
            path: r"%TEMP%".to_string(),
            user_specific: true,
        },
    ]
}

#[derive(Debug, Clone, Default)]
pub struct TempLocation {
    pub path: String,
    pub user_specific: bool,
}

pub fn scan_temp_directories() -> Result<TempScanResult, ForensicError> {
    Ok(TempScanResult {
        total_size: 0,
        file_count: 0,
        oldest_file: None,
        newest_file: None,
        locations: vec![],
    })
}

#[derive(Debug, Clone, Default)]
pub struct TempScanResult {
    pub total_size: u64,
    pub file_count: u32,
    pub oldest_file: Option<u64>,
    pub newest_file: Option<u64>,
    pub locations: Vec<TempLocationSummary>,
}

#[derive(Debug, Clone, Default)]
pub struct TempLocationSummary {
    pub path: String,
    pub size: u64,
    pub file_count: u32,
}

pub fn get_download_folder_contents() -> Result<Vec<DownloadedFile>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_DOWNLOAD_FOLDER_CONTENTS",
        "download_folder_contents.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| DownloadedFile {
            name: s(&v, &["name"]),
            path: s(&v, &["path"]),
            size: n(&v, &["size", "size_bytes"]),
            downloaded_time: n(&v, &["downloaded_time", "timestamp"]),
            source_url: s_opt(&v, &["source_url", "url"]),
        })
        .filter(|x| !x.path.is_empty() || !x.name.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct DownloadedFile {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub downloaded_time: u64,
    pub source_url: Option<String>,
}

fn category_enum(value: String) -> CleanupCategory {
    match value.to_ascii_lowercase().as_str() {
        "systemfiles" | "system_files" => CleanupCategory::SystemFiles,
        "downloadfiles" | "download_files" => CleanupCategory::DownloadFiles,
        "recyclebin" | "recycle_bin" => CleanupCategory::RecycleBin,
        "windowsupdate" | "windows_update" => CleanupCategory::WindowsUpdate,
        "devicedriver" | "device_driver" => CleanupCategory::DeviceDriver,
        "errorreports" | "error_reports" => CleanupCategory::ErrorReports,
        "windowsupgrade" | "windows_upgrade" => CleanupCategory::WindowsUpgrade,
        "offlinewebpages" | "offline_web_pages" => CleanupCategory::OfflineWebPages,
        _ => CleanupCategory::TemporaryFiles,
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("cleanup").join(file))
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

fn s_opt(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return Some(x.to_string());
        }
    }
    None
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

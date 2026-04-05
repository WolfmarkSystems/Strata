use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct SystemRestorePoint {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub restore_point_type: RestorePointType,
    pub creation_time: u64,
    pub snapshot_time: u64,
}

#[derive(Debug, Clone, Default)]
pub enum RestorePointType {
    #[default]
    ApplicationInstall,
    ApplicationUninstall,
    DesktopSetting,
    SystemSetting,
    RegisterSetting,
    CommandOperation,
    OemBios,
    SettingArchive,
    ManuallyCreated,
    CancelledOperation,
}

pub fn get_restore_points() -> Result<Vec<SystemRestorePoint>, ForensicError> {
    let Some(items) = load(path("FORENSIC_RESTORE_POINTS", "restore_points.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| SystemRestorePoint {
            id: n(&v, &["id", "restore_id"]) as u32,
            name: s(&v, &["name"]),
            description: s(&v, &["description"]),
            restore_point_type: point_type_enum(s(&v, &["restore_point_type", "type"])),
            creation_time: n(&v, &["creation_time", "created"]),
            snapshot_time: n(&v, &["snapshot_time", "timestamp"]),
        })
        .filter(|x| x.id > 0 || !x.name.is_empty())
        .collect())
}

pub fn get_latest_restore_point() -> Result<Option<SystemRestorePoint>, ForensicError> {
    let mut points = get_restore_points()?;
    points.sort_by_key(|p| p.snapshot_time.max(p.creation_time));
    Ok(points.pop())
}

pub fn get_restore_point_files(restore_id: u32) -> Result<Vec<RestoreFileInfo>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_RESTORE_POINT_FILES",
        "restore_point_files.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .filter(|v| {
            let id = n(v, &["restore_id", "id"]) as u32;
            restore_id == 0 || id == restore_id
        })
        .map(|v| RestoreFileInfo {
            file_path: s(&v, &["file_path", "path"]),
            original_size: n(&v, &["original_size", "size"]),
            restored_size: opt_n(&v, &["restored_size"]),
            status: s(&v, &["status"]),
        })
        .filter(|x| !x.file_path.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct RestoreFileInfo {
    pub file_path: String,
    pub original_size: u64,
    pub restored_size: Option<u64>,
    pub status: String,
}

pub fn get_restore_point_changes(restore_id: u32) -> Result<RestoreChanges, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_RESTORE_POINT_CHANGES",
        "restore_point_changes.json",
    )) else {
        return Ok(RestoreChanges {
            added_files: Vec::new(),
            modified_files: Vec::new(),
            deleted_files: Vec::new(),
        });
    };
    let matched = items.into_iter().find(|v| {
        let id = n(v, &["restore_id", "id"]) as u32;
        restore_id == 0 || id == restore_id
    });
    let Some(v) = matched else {
        return Ok(RestoreChanges {
            added_files: Vec::new(),
            modified_files: Vec::new(),
            deleted_files: Vec::new(),
        });
    };
    Ok(RestoreChanges {
        added_files: str_vec(&v, &["added_files"]),
        modified_files: str_vec(&v, &["modified_files"]),
        deleted_files: str_vec(&v, &["deleted_files"]),
    })
}

#[derive(Debug, Clone, Default)]
pub struct RestoreChanges {
    pub added_files: Vec<String>,
    pub modified_files: Vec<String>,
    pub deleted_files: Vec<String>,
}

pub fn check_restore_point_integrity(restore_id: u32) -> Result<bool, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_RESTORE_POINT_INTEGRITY",
        "restore_point_integrity.json",
    )) else {
        return Ok(true);
    };
    let matched = items.into_iter().find(|v| {
        let id = n(v, &["restore_id", "id"]) as u32;
        restore_id == 0 || id == restore_id
    });
    Ok(matched
        .as_ref()
        .and_then(|v| v.get("integrity_ok").and_then(Value::as_bool))
        .unwrap_or(true))
}

fn point_type_enum(value: String) -> RestorePointType {
    match value.to_ascii_lowercase().as_str() {
        "applicationuninstall" | "application_uninstall" => RestorePointType::ApplicationUninstall,
        "desktopsetting" | "desktop_setting" => RestorePointType::DesktopSetting,
        "systemsetting" | "system_setting" => RestorePointType::SystemSetting,
        "registersetting" | "register_setting" => RestorePointType::RegisterSetting,
        "commandoperation" | "command_operation" => RestorePointType::CommandOperation,
        "oembios" | "oem_bios" => RestorePointType::OemBios,
        "settingarchive" | "setting_archive" => RestorePointType::SettingArchive,
        "manuallycreated" | "manually_created" => RestorePointType::ManuallyCreated,
        "cancelledoperation" | "cancelled_operation" => RestorePointType::CancelledOperation,
        _ => RestorePointType::ApplicationInstall,
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("restoration").join(file))
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

use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

pub fn get_system_restore_settings() -> Result<RestoreSettings, ForensicError> {
    let path = env::var("FORENSIC_SYSTEM_RESTORE_SETTINGS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("restoration")
                .join("system_restore_settings.json")
        });
    let Ok(data) = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
    else {
        return Ok(RestoreSettings {
            enabled: false,
            disk_space: 0,
        });
    };
    let Ok(v) = serde_json::from_slice::<Value>(&data) else {
        return Ok(RestoreSettings {
            enabled: false,
            disk_space: 0,
        });
    };
    Ok(RestoreSettings {
        enabled: v.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        disk_space: v.get("disk_space").and_then(Value::as_u64).unwrap_or(0),
    })
}

#[derive(Debug, Clone, Default)]
pub struct RestoreSettings {
    pub enabled: bool,
    pub disk_space: u64,
}

pub fn get_restore_points_count() -> u32 {
    let path = env::var("FORENSIC_SYSTEM_RESTORE_POINTS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("restoration")
                .join("restore_points.json")
        });
    let Ok(data) = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
    else {
        return 0;
    };
    let Ok(v) = serde_json::from_slice::<Value>(&data) else {
        return 0;
    };
    if let Some(items) = v.as_array() {
        items.len() as u32
    } else if let Some(n) = v.get("count").and_then(Value::as_u64) {
        n as u32
    } else {
        0
    }
}

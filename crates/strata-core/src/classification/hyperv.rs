use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

pub fn get_hyperv_info() -> Result<HyperVInfo, ForensicError> {
    let path = env::var("FORENSIC_HYPERV_INFO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("hyperv").join("info.json"));
    let Ok(data) = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
    else {
        return Ok(HyperVInfo {
            enabled: false,
            version: String::new(),
        });
    };
    let Ok(v) = serde_json::from_slice::<Value>(&data) else {
        return Ok(HyperVInfo {
            enabled: false,
            version: String::new(),
        });
    };
    Ok(HyperVInfo {
        enabled: v.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        version: v
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct HyperVInfo {
    pub enabled: bool,
    pub version: String,
}

pub fn get_vms() -> Vec<String> {
    let path = env::var("FORENSIC_HYPERV_VMS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("hyperv").join("vms.json"));
    let Ok(data) = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
    else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_slice::<Value>(&data) else {
        return Vec::new();
    };
    if let Some(items) = v.as_array() {
        return items
            .iter()
            .filter_map(|x| {
                x.as_str().map(ToString::to_string).or_else(|| {
                    x.get("name")
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                })
            })
            .collect();
    }
    Vec::new()
}

use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_bitlocker_protected_volumes() -> Vec<BitlockerVolume> {
    let Some(items) = load(path("FORENSIC_BITLOCKER_VOLUMES", "bitlocker_volumes.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| BitlockerVolume {
            drive_letter: s(&v, &["drive_letter", "mount_point", "volume"]),
            protection_status: s(&v, &["protection_status", "status"]),
        })
        .filter(|x| !x.drive_letter.is_empty() || !x.protection_status.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct BitlockerVolume {
    pub drive_letter: String,
    pub protection_status: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("encryption").join(file))
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

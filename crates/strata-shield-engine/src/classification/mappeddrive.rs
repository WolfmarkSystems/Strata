use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_mapped_drives() -> Vec<MappedDrive> {
    let Some(items) = load(path("FORENSIC_MAPPED_DRIVES", "mapped_drives.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| MappedDrive {
            drive_letter: s(&v, &["drive_letter", "letter"]),
            remote_path: s(&v, &["remote_path", "path"]),
        })
        .filter(|x| !x.drive_letter.is_empty() || !x.remote_path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct MappedDrive {
    pub drive_letter: String,
    pub remote_path: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("network").join(file))
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

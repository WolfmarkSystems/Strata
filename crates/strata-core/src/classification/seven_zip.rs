use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_7zip_history() -> Vec<SevenZipHistory> {
    let Some(items) = load(path("FORENSIC_7ZIP_HISTORY", "7zip_history.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SevenZipHistory {
            archive_path: s(&v, &["archive_path", "path"]),
            operation: s(&v, &["operation", "op"]),
            timestamp: n(&v, &["timestamp", "time"]),
            result: s(&v, &["result", "status"]),
            files_affected: n(&v, &["files_affected", "count"]) as u32,
        })
        .filter(|x| !x.archive_path.is_empty() || x.timestamp > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SevenZipHistory {
    pub archive_path: String,
    pub operation: String,
    pub timestamp: u64,
    pub result: String,
    pub files_affected: u32,
}

pub fn get_7zip_profiles() -> Vec<SevenZipProfile> {
    let Some(items) = load(path("FORENSIC_7ZIP_PROFILES", "7zip_profiles.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SevenZipProfile {
            name: s(&v, &["name", "profile"]),
            compression_level: n(&v, &["compression_level", "level"]) as u32,
            method: s(&v, &["method"]),
            encryption: b(&v, &["encryption", "encrypted"]),
        })
        .filter(|x| !x.name.is_empty() || !x.method.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SevenZipProfile {
    pub name: String,
    pub compression_level: u32,
    pub method: String,
    pub encryption: bool,
}

pub fn get_7zip_favorites() -> Vec<SevenZipFavorite> {
    let Some(items) = load(path("FORENSIC_7ZIP_FAVORITES", "7zip_favorites.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SevenZipFavorite {
            name: s(&v, &["name"]),
            path: s(&v, &["path"]),
            added: n(&v, &["added", "timestamp"]),
        })
        .filter(|x| !x.name.is_empty() || !x.path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SevenZipFavorite {
    pub name: String,
    pub path: String,
    pub added: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("archives").join(file))
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
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return n;
            }
        }
    }
    0
}

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}

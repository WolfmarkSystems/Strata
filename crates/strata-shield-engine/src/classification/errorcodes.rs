use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_windows_error_codes() -> Vec<ErrorCode> {
    let Some(items) = load(path(
        "FORENSIC_WINDOWS_ERROR_CODES",
        "windows_error_codes.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| ErrorCode {
            code: n(&v, &["code"]) as u32,
            name: s(&v, &["name"]),
            description: s(&v, &["description", "message"]),
        })
        .filter(|x| x.code > 0 || !x.name.is_empty() || !x.description.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ErrorCode {
    pub code: u32,
    pub name: String,
    pub description: String,
}

pub fn lookup_error_code(_code: u32) -> Option<ErrorCode> {
    get_windows_error_codes()
        .into_iter()
        .find(|x| x.code == _code)
}

pub fn get_stop_codes() -> Vec<StopCode> {
    let Some(items) = load(path(
        "FORENSIC_WINDOWS_STOP_CODES",
        "windows_stop_codes.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| StopCode {
            code: n(&v, &["code"]) as u32,
            name: s(&v, &["name"]),
            description: s(&v, &["description", "message"]),
        })
        .filter(|x| x.code > 0 || !x.name.is_empty() || !x.description.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct StopCode {
    pub code: u32,
    pub name: String,
    pub description: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("system").join(file))
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

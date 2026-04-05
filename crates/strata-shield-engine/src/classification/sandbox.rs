use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct SandboxSession {
    pub id: String,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub memory_limit: u64,
    pub network_enabled: bool,
    pub mapped_folders: Vec<String>,
}

pub fn get_sandbox_history() -> Result<Vec<SandboxSession>, ForensicError> {
    let Some(items) = load(path("FORENSIC_SANDBOX_HISTORY", "sandbox_history.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(parse_session)
        .filter(|x| !x.id.is_empty() || x.start_time > 0)
        .collect())
}

pub fn get_sandbox_settings() -> Result<SandboxSettings, ForensicError> {
    Ok(SandboxSettings {
        default_network: true,
        default_memory: 4096,
        default_vgpu: true,
    })
}

#[derive(Debug, Clone, Default)]
pub struct SandboxSettings {
    pub default_network: bool,
    pub default_memory: u64,
    pub default_vgpu: bool,
}

pub fn is_sandbox_available() -> bool {
    false
}

pub fn get_sandbox_log_path() -> String {
    r"C:\Users\Default\AppData\Local\Packages\WindowsSandbox_D2BR463A2A3F\Temp\Sandbox.log"
        .to_string()
}

pub fn get_sandbox_previous_sessions() -> Result<Vec<SandboxSession>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_SANDBOX_PREVIOUS_SESSIONS",
        "sandbox_previous_sessions.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(parse_session)
        .filter(|x| !x.id.is_empty() || x.start_time > 0)
        .collect())
}

fn parse_session(v: Value) -> SandboxSession {
    SandboxSession {
        id: s(&v, &["id", "session_id"]),
        start_time: n(&v, &["start_time", "started_at"]),
        end_time: opt_n(&v, &["end_time", "ended_at"]),
        memory_limit: n(&v, &["memory_limit", "memory_mb"]),
        network_enabled: b(&v, &["network_enabled", "network"]),
        mapped_folders: str_vec(&v, &["mapped_folders", "folders"]),
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("sandbox").join(file))
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

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
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

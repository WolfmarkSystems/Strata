use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_etw_sessions() -> Vec<EtwSessionInfo> {
    let Some(items) = load(path("FORENSIC_ETW_DEEP_SESSIONS", "sessions.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| EtwSessionInfo {
            name: s(&v, &["name", "session_name"]),
            logfile_mode: n(&v, &["logfile_mode"]) as u32,
            buffer_size: n(&v, &["buffer_size"]) as u32,
            providers: providers(&v),
        })
        .filter(|x| !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct EtwSessionInfo {
    pub name: String,
    pub logfile_mode: u32,
    pub buffer_size: u32,
    pub providers: Vec<EtwProviderInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct EtwProviderInfo {
    pub guid: String,
    pub enabled: u8,
    pub level: u8,
}

pub fn get_etw_traces() -> Vec<EtwTrace> {
    let Some(items) = load(path("FORENSIC_ETW_DEEP_TRACES", "traces.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| EtwTrace {
            session_name: s(&v, &["session_name"]),
            trace_file: s(&v, &["trace_file", "path"]),
            start_time: n(&v, &["start_time", "start"]),
            end_time: opt_n(&v, &["end_time", "end"]),
            event_count: n(&v, &["event_count", "events"]),
        })
        .filter(|x| !x.session_name.is_empty() || !x.trace_file.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct EtwTrace {
    pub session_name: String,
    pub trace_file: String,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub event_count: u64,
}

pub fn parse_etl_events() -> Vec<EtlEventData> {
    let Some(items) = load(path("FORENSIC_ETW_DEEP_EVENTS", "etl_events.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| EtlEventData {
            timestamp: n(&v, &["timestamp", "time"]),
            provider: s(&v, &["provider", "provider_name"]),
            event_id: n(&v, &["event_id", "id"]) as u16,
            data: bytes(&v, &["data", "payload"]),
        })
        .filter(|x| x.timestamp > 0 || !x.provider.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct EtlEventData {
    pub timestamp: u64,
    pub provider: String,
    pub event_id: u16,
    pub data: Vec<u8>,
}

pub fn get_wpp_traces() -> Vec<WppTrace> {
    let Some(items) = load(path("FORENSIC_ETW_DEEP_WPP", "wpp_traces.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WppTrace {
            provider: s(&v, &["provider"]),
            file_path: s(&v, &["file_path", "path"]),
            pdb_path: s(&v, &["pdb_path"]),
        })
        .filter(|x| !x.provider.is_empty() || !x.file_path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WppTrace {
    pub provider: String,
    pub file_path: String,
    pub pdb_path: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("etw").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
}

fn providers(v: &Value) -> Vec<EtwProviderInfo> {
    let Some(items) = v.get("providers").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|x| EtwProviderInfo {
            guid: s(x, &["guid", "provider_id"]),
            enabled: if b(x, &["enabled"]) { 1 } else { 0 },
            level: n(x, &["level"]) as u8,
        })
        .filter(|x| !x.guid.is_empty())
        .collect()
}

fn bytes(v: &Value, keys: &[&str]) -> Vec<u8> {
    for key in keys {
        if let Some(items) = v.get(*key).and_then(Value::as_array) {
            return items
                .iter()
                .filter_map(Value::as_u64)
                .filter_map(|n| u8::try_from(n).ok())
                .collect();
        }
    }
    Vec::new()
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

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
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

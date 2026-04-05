use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_security_events() -> Vec<SecurityEvent> {
    let Some(items) = load(path("FORENSIC_SECURITY_EVENTS", "security_events.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SecurityEvent {
            event_id: n(&v, &["event_id", "id"]) as u32,
            timestamp: n(&v, &["timestamp", "time_created", "occurred_utc"]),
        })
        .filter(|x| x.event_id > 0 || x.timestamp > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SecurityEvent {
    pub event_id: u32,
    pub timestamp: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("events").join(file))
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

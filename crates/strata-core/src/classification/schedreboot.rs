use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_scheduled_reboots() -> Vec<ScheduledReboot> {
    let Some(items) = load(path("FORENSIC_SCHEDULED_REBOOTS", "scheduled_reboots.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| ScheduledReboot {
            time: n(&v, &["time", "timestamp", "scheduled_utc"]),
            reason: s(&v, &["reason", "message"]),
        })
        .filter(|x| x.time > 0 || !x.reason.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ScheduledReboot {
    pub time: u64,
    pub reason: String,
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

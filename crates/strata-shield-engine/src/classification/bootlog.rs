use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_boot_log() -> BootLog {
    let path = path("FORENSIC_BOOT_LOG", "boot_log.json");
    let data = match super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return BootLog::default(),
    };
    let json: Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return BootLog::default(),
    };

    let events = if let Some(items) = json.as_array() {
        parse_events(items)
    } else if let Some(items) = json.get("events").and_then(Value::as_array) {
        parse_events(items)
    } else {
        Vec::new()
    };

    BootLog { events }
}

#[derive(Debug, Clone, Default)]
pub struct BootLog {
    pub events: Vec<BootEvent>,
}

#[derive(Debug, Clone, Default)]
pub struct BootEvent {
    pub time: u64,
    pub message: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("boot").join(file))
}

fn parse_events(items: &[Value]) -> Vec<BootEvent> {
    items
        .iter()
        .map(|v| BootEvent {
            time: n(v, &["time", "timestamp", "timestamp_utc"]),
            message: s(v, &["message", "event"]),
        })
        .filter(|x| x.time > 0 || !x.message.is_empty())
        .collect()
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

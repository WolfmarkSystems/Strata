use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_registry_snapshots() -> Vec<RegistrySnapshot> {
    let Some(items) = load(path(
        "FORENSIC_LIVE_REGISTRY_SNAPSHOTS",
        "registry_snapshots.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| RegistrySnapshot {
            timestamp: n(&v, &["timestamp", "time"]),
            key: s(&v, &["key", "path"]),
            values: values(&v),
        })
        .filter(|x| x.timestamp > 0 || !x.key.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct RegistrySnapshot {
    pub timestamp: u64,
    pub key: String,
    pub values: Vec<RegistryValue>,
}

#[derive(Debug, Clone, Default)]
pub struct RegistryValue {
    pub name: String,
    pub data_type: String,
    pub data: Vec<u8>,
}

pub fn get_run_keys() -> Vec<RunKey> {
    let Some(items) = load(path("FORENSIC_LIVE_RUN_KEYS", "run_keys.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| RunKey {
            hive: s(&v, &["hive"]),
            path: s(&v, &["path", "key_path"]),
            value_name: s(&v, &["value_name", "name"]),
            command: s(&v, &["command", "data"]),
        })
        .filter(|x| !x.path.is_empty() || !x.command.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct RunKey {
    pub hive: String,
    pub path: String,
    pub value_name: String,
    pub command: String,
}

pub fn get_services() -> Vec<LiveService> {
    let Some(items) = load(path("FORENSIC_LIVE_SERVICES", "services.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| LiveService {
            name: s(&v, &["name", "service_name"]),
            display_name: s(&v, &["display_name"]),
            status: s(&v, &["status", "state"]),
            start_type: s(&v, &["start_type"]),
            path: s(&v, &["path", "image_path"]),
        })
        .filter(|x| !x.name.is_empty() || !x.display_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct LiveService {
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub start_type: String,
    pub path: String,
}

pub fn get_scheduled_tasks() -> Vec<LiveTask> {
    let Some(items) = load(path("FORENSIC_LIVE_TASKS", "scheduled_tasks.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| LiveTask {
            name: s(&v, &["name", "task_name"]),
            path: s(&v, &["path", "task_path"]),
            state: s(&v, &["state", "status"]),
            last_run: n(&v, &["last_run", "last_run_time"]),
            next_run: n(&v, &["next_run", "next_run_time"]),
        })
        .filter(|x| !x.name.is_empty() || !x.path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct LiveTask {
    pub name: String,
    pub path: String,
    pub state: String,
    pub last_run: u64,
    pub next_run: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("live").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
}

fn values(v: &Value) -> Vec<RegistryValue> {
    let Some(items) = v.get("values").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|x| RegistryValue {
            name: s(x, &["name", "value_name"]),
            data_type: s(x, &["data_type", "type"]),
            data: bytes(x, &["data", "bytes"]),
        })
        .filter(|x| !x.name.is_empty() || !x.data.is_empty())
        .collect()
}

fn bytes(v: &Value, keys: &[&str]) -> Vec<u8> {
    for k in keys {
        if let Some(items) = v.get(*k).and_then(Value::as_array) {
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

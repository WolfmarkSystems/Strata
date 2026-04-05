use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_minifilters() -> Vec<Minifilter> {
    let Some(items) = load(path("FORENSIC_KERNEL_MINIFILTERS", "minifilters.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| Minifilter {
            altitude: s(&v, &["altitude"]),
            name: s(&v, &["name"]),
            instance: n(&v, &["instance"]) as u32,
            status: s(&v, &["status"]),
        })
        .filter(|x| !x.name.is_empty() || !x.altitude.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct Minifilter {
    pub altitude: String,
    pub name: String,
    pub instance: u32,
    pub status: String,
}

pub fn get_callbacks() -> Vec<KernelCallback> {
    let Some(items) = load(path("FORENSIC_KERNEL_CALLBACKS", "callbacks.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| KernelCallback {
            callback_type: s(&v, &["callback_type", "type"]),
            driver: s(&v, &["driver"]),
            address: n(&v, &["address"]),
            module: s(&v, &["module"]),
        })
        .filter(|x| x.address > 0 || !x.callback_type.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct KernelCallback {
    pub callback_type: String,
    pub driver: String,
    pub address: u64,
    pub module: String,
}

pub fn get_ps2_callbacks() -> Vec<Ps2Callback> {
    let Some(items) = load(path("FORENSIC_KERNEL_PS2_CALLBACKS", "ps2_callbacks.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| Ps2Callback {
            callback_type: s(&v, &["callback_type", "type"]),
            driver: s(&v, &["driver"]),
            address: n(&v, &["address"]),
        })
        .filter(|x| x.address > 0 || !x.driver.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct Ps2Callback {
    pub callback_type: String,
    pub driver: String,
    pub address: u64,
}

pub fn get_object_callbacks() -> Vec<ObjectCallback> {
    let Some(items) = load(path(
        "FORENSIC_KERNEL_OBJECT_CALLBACKS",
        "object_callbacks.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| ObjectCallback {
            object_type: s(&v, &["object_type", "type"]),
            driver: s(&v, &["driver"]),
            address: n(&v, &["address"]),
            operations: sa(&v, &["operations", "ops"]),
        })
        .filter(|x| !x.object_type.is_empty() || x.address > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ObjectCallback {
    pub object_type: String,
    pub driver: String,
    pub address: u64,
    pub operations: Vec<String>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("kernel").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
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

fn sa(v: &Value, keys: &[&str]) -> Vec<String> {
    for k in keys {
        if let Some(items) = v.get(*k).and_then(Value::as_array) {
            return items
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
        }
    }
    Vec::new()
}

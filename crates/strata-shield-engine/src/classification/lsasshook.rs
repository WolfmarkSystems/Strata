use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_lsass_hooks() -> Vec<LsassHook> {
    let Some(items) = load(path("FORENSIC_LSASS_HOOKS", "lsass_hooks.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| LsassHook {
            dll: s(&v, &["dll", "module"]),
            address: n(&v, &["address", "hook_address"]),
        })
        .filter(|x| !x.dll.is_empty() || x.address > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct LsassHook {
    pub dll: String,
    pub address: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("memory").join(file))
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

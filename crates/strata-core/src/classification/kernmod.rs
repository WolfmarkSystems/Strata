use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_kernel_modules() -> Vec<KernelModule> {
    let Some(items) = load(path("FORENSIC_KERNEL_MODULES", "kernel_modules.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| KernelModule {
            name: s(&v, &["name", "module_name"]),
            address: n(&v, &["address", "base"]),
        })
        .filter(|x| !x.name.is_empty() || x.address > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct KernelModule {
    pub name: String,
    pub address: u64,
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

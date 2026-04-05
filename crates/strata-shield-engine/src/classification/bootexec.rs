use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_boot_execution() -> Vec<BootExecute> {
    let Some(items) = load(path("FORENSIC_BOOT_EXECUTE", "boot_execute.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .enumerate()
        .map(|(idx, v)| BootExecute {
            command: s(&v, &["command", "cmd"]),
            order: n(&v, &["order"]).unwrap_or(idx as u32),
        })
        .filter(|x| !x.command.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct BootExecute {
    pub command: String,
    pub order: u32,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("boot").join(file))
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

fn n(v: &Value, keys: &[&str]) -> Option<u32> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            if let Ok(out) = u32::try_from(x) {
                return Some(out);
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(out) = x.parse::<u32>() {
                return Some(out);
            }
        }
    }
    None
}

use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_env_blocks() -> Vec<EnvBlock> {
    let Some(items) = load(path("FORENSIC_ENV_BLOCKS", "env_blocks.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| EnvBlock {
            process_id: n(&v, &["process_id", "pid"]) as u32,
            variables: vars(&v),
        })
        .filter(|x| x.process_id > 0 || !x.variables.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct EnvBlock {
    pub process_id: u32,
    pub variables: Vec<(String, String)>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("env").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
}

fn vars(v: &Value) -> Vec<(String, String)> {
    if let Some(obj) = v.get("variables").and_then(Value::as_object) {
        return obj
            .iter()
            .map(|(k, val)| {
                let value = val
                    .as_str()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| val.to_string());
                (k.clone(), value)
            })
            .collect();
    }
    Vec::new()
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

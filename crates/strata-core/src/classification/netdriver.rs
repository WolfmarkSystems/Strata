use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_network_drivers() -> Vec<NetworkDriver> {
    let Some(items) = load(path("FORENSIC_NETWORK_DRIVERS", "network_drivers.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| NetworkDriver {
            name: s(&v, &["name", "driver_name"]),
            version: s(&v, &["version"]),
        })
        .filter(|x| !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct NetworkDriver {
    pub name: String,
    pub version: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("network").join(file))
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

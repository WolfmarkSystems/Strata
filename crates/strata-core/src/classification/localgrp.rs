use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_local_groups() -> Vec<LocalGroup> {
    let Some(items) = load(path("FORENSIC_LOCAL_GROUPS", "local_groups.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| LocalGroup {
            name: s(&v, &["name", "group_name"]),
            members: sa(&v, &["members"]),
        })
        .filter(|x| !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct LocalGroup {
    pub name: String,
    pub members: Vec<String>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("accounts").join(file))
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

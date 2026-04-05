use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_winsxs_contents() -> Vec<WinsxsItem> {
    let Some(items) = load(path("FORENSIC_WINSXS_CONTENTS", "winsxs_contents.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WinsxsItem {
            name: s(&v, &["name", "component"]),
            path: s(&v, &["path", "component_path"]),
        })
        .filter(|x| !x.name.is_empty() || !x.path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WinsxsItem {
    pub name: String,
    pub path: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("system").join(file))
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

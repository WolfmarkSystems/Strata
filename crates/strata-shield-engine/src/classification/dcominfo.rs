use std::env;
use std::path::PathBuf;

use serde_json::Value;

#[allow(non_snake_case)]
pub fn get_dcomApplications() -> Vec<DcomApp> {
    let Some(items) = load(path("FORENSIC_DCOM_APPS", "dcom_apps.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DcomApp {
            name: s(&v, &["name", "application_name"]),
            app_id: s(&v, &["app_id", "appid"]),
        })
        .filter(|x| !x.app_id.is_empty() || !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct DcomApp {
    pub name: String,
    pub app_id: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("com").join(file))
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

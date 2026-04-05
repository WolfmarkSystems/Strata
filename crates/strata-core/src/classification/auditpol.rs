use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_audit_policies() -> Vec<AuditPolicy> {
    let Some(items) = load(path("FORENSIC_AUDIT_POLICIES", "audit_policies.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AuditPolicy {
            category: s(&v, &["category", "name"]),
            setting: s(&v, &["setting", "value"]),
        })
        .filter(|x| !x.category.is_empty() || !x.setting.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AuditPolicy {
    pub category: String,
    pub setting: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("security").join(file))
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

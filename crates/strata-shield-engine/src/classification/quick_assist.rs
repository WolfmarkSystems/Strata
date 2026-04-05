use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_quick_assist_sessions() -> Vec<QuickAssistSession> {
    let Some(items) = load(path(
        "FORENSIC_QUICK_ASSIST_SESSIONS",
        "quick_assist_sessions.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| QuickAssistSession {
            session_id: s(&v, &["session_id", "id"]),
            role: s(&v, &["role"]),
            started: n(&v, &["started", "start_time"]),
            ended: opt_n(&v, &["ended", "end_time"]),
            other_party: s(&v, &["other_party", "peer"]),
        })
        .filter(|x| !x.session_id.is_empty() || x.started > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct QuickAssistSession {
    pub session_id: String,
    pub role: String,
    pub started: u64,
    pub ended: Option<u64>,
    pub other_party: String,
}

pub fn get_quick_assist_permissions() -> Vec<QuickAssistPermission> {
    let Some(items) = load(path(
        "FORENSIC_QUICK_ASSIST_PERMISSIONS",
        "quick_assist_permissions.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| QuickAssistPermission {
            permission: s(&v, &["permission", "name"]),
            granted: b(&v, &["granted", "enabled"]),
            timestamp: n(&v, &["timestamp", "time"]),
        })
        .filter(|x| !x.permission.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct QuickAssistPermission {
    pub permission: String,
    pub granted: bool,
    pub timestamp: u64,
}

pub fn get_quick_assist_history() -> Vec<QuickAssistHistory> {
    let Some(items) = load(path(
        "FORENSIC_QUICK_ASSIST_HISTORY",
        "quick_assist_history.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| QuickAssistHistory {
            timestamp: n(&v, &["timestamp", "time"]),
            action: s(&v, &["action"]),
            details: s(&v, &["details", "message"]),
        })
        .filter(|x| !x.action.is_empty() || x.timestamp > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct QuickAssistHistory {
    pub timestamp: u64,
    pub action: String,
    pub details: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("quick_assist").join(file))
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

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}

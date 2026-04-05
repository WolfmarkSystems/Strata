use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_signal_messages() -> Vec<SignalMessage> {
    let path = path_for("FORENSIC_SIGNAL_MESSAGES", "signal_messages.json");
    let Some(items) = load(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SignalMessage {
            id: s(&v, &["id", "message_id"]),
            sender: s(&v, &["sender", "from"]),
            body: s(&v, &["body", "text"]),
            timestamp: n(&v, &["timestamp", "ts"]),
            attachments: sa(&v, &["attachments"]),
        })
        .filter(|x| !x.id.is_empty() || !x.body.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SignalMessage {
    pub id: String,
    pub sender: String,
    pub body: String,
    pub timestamp: u64,
    pub attachments: Vec<String>,
}

pub fn get_signal_contacts() -> Vec<SignalContact> {
    let path = path_for("FORENSIC_SIGNAL_CONTACTS", "signal_contacts.json");
    let Some(items) = load(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SignalContact {
            uuid: s(&v, &["uuid", "id"]),
            name: s(&v, &["name", "display_name"]),
            phone: s(&v, &["phone", "number"]),
        })
        .filter(|x| !x.uuid.is_empty() || !x.phone.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SignalContact {
    pub uuid: String,
    pub name: String,
    pub phone: String,
}

pub fn get_signal_groups() -> Vec<SignalGroup> {
    let path = path_for("FORENSIC_SIGNAL_GROUPS", "signal_groups.json");
    let Some(items) = load(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SignalGroup {
            id: s(&v, &["id", "group_id"]),
            name: s(&v, &["name", "title"]),
            members: sa(&v, &["members"]),
        })
        .filter(|x| !x.id.is_empty() || !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SignalGroup {
    pub id: String,
    pub name: String,
    pub members: Vec<String>,
}

fn path_for(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("chat").join(file))
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
fn sa(v: &Value, keys: &[&str]) -> Vec<String> {
    for k in keys {
        if let Some(arr) = v.get(*k).and_then(Value::as_array) {
            return arr
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
        }
    }
    Vec::new()
}

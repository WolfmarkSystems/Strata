use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_viber_messages() -> Vec<ViberMessage> {
    let Some(items) = load(path("FORENSIC_VIBER_MESSAGES", "viber_messages.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| ViberMessage {
            token: strv(&v, &["token", "id"]),
            sender: strv(&v, &["sender", "from"]),
            body: strv(&v, &["body", "text"]),
            timestamp: numv(&v, &["timestamp", "ts"]),
            msg_type: strv(&v, &["msg_type", "type"]),
        })
        .filter(|x| !x.token.is_empty() || !x.body.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ViberMessage {
    pub token: String,
    pub sender: String,
    pub body: String,
    pub timestamp: u64,
    pub msg_type: String,
}

pub fn get_viber_contacts() -> Vec<ViberContact> {
    let Some(items) = load(path("FORENSIC_VIBER_CONTACTS", "viber_contacts.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| ViberContact {
            number: strv(&v, &["number", "phone"]),
            name: strv(&v, &["name", "display_name"]),
            avatar: vec_bytes(&v, &["avatar"]),
        })
        .filter(|x| !x.number.is_empty() || !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ViberContact {
    pub number: String,
    pub name: String,
    pub avatar: Vec<u8>,
}

pub fn get_viber_calls() -> Vec<ViberCall> {
    let Some(items) = load(path("FORENSIC_VIBER_CALLS", "viber_calls.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| ViberCall {
            caller: strv(&v, &["caller", "from"]),
            callee: strv(&v, &["callee", "to"]),
            start_time: numv(&v, &["start_time", "timestamp"]),
            duration: numv(&v, &["duration"]),
        })
        .filter(|x| !x.caller.is_empty() || x.start_time > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ViberCall {
    pub caller: String,
    pub callee: String,
    pub start_time: u64,
    pub duration: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
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
fn strv(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(Value::as_str) {
            return s.to_string();
        }
    }
    String::new()
}
fn numv(v: &Value, keys: &[&str]) -> u64 {
    for k in keys {
        if let Some(n) = v.get(*k).and_then(Value::as_u64) {
            return n;
        }
        if let Some(s) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = s.parse::<u64>() {
                return n;
            }
        }
    }
    0
}
fn vec_bytes(v: &Value, keys: &[&str]) -> Vec<u8> {
    for k in keys {
        if let Some(arr) = v.get(*k).and_then(Value::as_array) {
            return arr
                .iter()
                .filter_map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
        }
    }
    Vec::new()
}

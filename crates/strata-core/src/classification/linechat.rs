use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_line_messages() -> Vec<LineMessage> {
    let Some(items) = load(data_path("FORENSIC_LINE_MESSAGES", "line_messages.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| LineMessage {
            chat_id: s(&v, &["chat_id", "conversation_id"]),
            sender_id: s(&v, &["sender_id", "from"]),
            text: s(&v, &["text", "message"]),
            timestamp: n(&v, &["timestamp", "ts"]),
            has_content: b(&v, &["has_content", "has_media"]),
        })
        .filter(|x| !x.chat_id.is_empty() || !x.text.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct LineMessage {
    pub chat_id: String,
    pub sender_id: String,
    pub text: String,
    pub timestamp: u64,
    pub has_content: bool,
}

pub fn get_line_contacts() -> Vec<LineContact> {
    let Some(items) = load(data_path("FORENSIC_LINE_CONTACTS", "line_contacts.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| LineContact {
            user_id: s(&v, &["user_id", "id"]),
            display_name: s(&v, &["display_name", "name"]),
            phones: sa(&v, &["phones", "numbers"]),
        })
        .filter(|x| !x.user_id.is_empty() || !x.display_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct LineContact {
    pub user_id: String,
    pub display_name: String,
    pub phones: Vec<String>,
}

pub fn get_line_groups() -> Vec<LineGroup> {
    let Some(items) = load(data_path("FORENSIC_LINE_GROUPS", "line_groups.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| LineGroup {
            group_id: s(&v, &["group_id", "id"]),
            name: s(&v, &["name", "title"]),
            members: sa(&v, &["members"]),
        })
        .filter(|x| !x.group_id.is_empty() || !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct LineGroup {
    pub group_id: String,
    pub name: String,
    pub members: Vec<String>,
}

fn data_path(env_key: &str, file: &str) -> PathBuf {
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
        if let Some(s) = v.get(*k).and_then(Value::as_str) {
            return s.to_string();
        }
    }
    String::new()
}
fn n(v: &Value, keys: &[&str]) -> u64 {
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
fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(b) = v.get(*k).and_then(Value::as_bool) {
            return b;
        }
    }
    false
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

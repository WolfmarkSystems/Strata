use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_whatsapp_messages() -> Vec<WhatsAppMessage> {
    let Some(items) = load(path("FORENSIC_WHATSAPP_MESSAGES", "whatsapp_messages.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WhatsAppMessage {
            id: s(&v, &["id", "message_id"]),
            sender: s(&v, &["sender", "from"]),
            message: s(&v, &["message", "text", "body"]),
            timestamp: n(&v, &["timestamp", "ts"]),
            is_from_me: b(&v, &["is_from_me", "from_me"]),
            has_attachment: b(&v, &["has_attachment", "has_media"]),
        })
        .filter(|x| !x.id.is_empty() || !x.message.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WhatsAppMessage {
    pub id: String,
    pub sender: String,
    pub message: String,
    pub timestamp: u64,
    pub is_from_me: bool,
    pub has_attachment: bool,
}

pub fn get_whatsapp_contacts() -> Vec<WhatsAppContact> {
    let Some(items) = load(path("FORENSIC_WHATSAPP_CONTACTS", "whatsapp_contacts.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WhatsAppContact {
            jid: s(&v, &["jid", "id"]),
            display_name: s(&v, &["display_name", "name"]),
            status: s(&v, &["status"]),
        })
        .filter(|x| !x.jid.is_empty() || !x.display_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WhatsAppContact {
    pub jid: String,
    pub display_name: String,
    pub status: String,
}

pub fn get_whatsapp_calls() -> Vec<WhatsAppCall> {
    let Some(items) = load(path("FORENSIC_WHATSAPP_CALLS", "whatsapp_calls.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WhatsAppCall {
            id: s(&v, &["id", "call_id"]),
            caller: s(&v, &["caller", "from"]),
            duration: n(&v, &["duration"]) as u32,
            timestamp: n(&v, &["timestamp", "start_time"]),
        })
        .filter(|x| !x.id.is_empty() || x.timestamp > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WhatsAppCall {
    pub id: String,
    pub caller: String,
    pub duration: u32,
    pub timestamp: u64,
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
fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}

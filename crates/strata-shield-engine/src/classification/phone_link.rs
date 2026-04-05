use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_phone_link_devices() -> Vec<PhoneLinkDevice> {
    let Some(items) = load(path("FORENSIC_PHONE_LINK_DEVICES", "devices.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| PhoneLinkDevice {
            device_id: s(&v, &["device_id", "id"]),
            device_name: s(&v, &["device_name", "name"]),
            os: s(&v, &["os", "platform"]),
            paired: n(&v, &["paired", "paired_at"]),
            last_connected: n(&v, &["last_connected", "last_seen"]),
            battery: n(&v, &["battery", "battery_percent"]) as u32,
        })
        .filter(|x| !x.device_id.is_empty() || !x.device_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct PhoneLinkDevice {
    pub device_id: String,
    pub device_name: String,
    pub os: String,
    pub paired: u64,
    pub last_connected: u64,
    pub battery: u32,
}

pub fn get_phone_link_notifications() -> Vec<PhoneLinkNotification> {
    let Some(items) = load(path(
        "FORENSIC_PHONE_LINK_NOTIFICATIONS",
        "notifications.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| PhoneLinkNotification {
            device: s(&v, &["device", "device_name"]),
            app: s(&v, &["app", "app_name"]),
            title: s(&v, &["title"]),
            text: s(&v, &["text", "body"]),
            timestamp: n(&v, &["timestamp", "time"]),
            read: b(&v, &["read", "is_read"]),
        })
        .filter(|x| !x.title.is_empty() || !x.text.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct PhoneLinkNotification {
    pub device: String,
    pub app: String,
    pub title: String,
    pub text: String,
    pub timestamp: u64,
    pub read: bool,
}

pub fn get_phone_link_messages() -> Vec<PhoneLinkMessage> {
    let Some(items) = load(path("FORENSIC_PHONE_LINK_MESSAGES", "messages.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| PhoneLinkMessage {
            device: s(&v, &["device", "device_name"]),
            contact: s(&v, &["contact", "contact_name"]),
            body: s(&v, &["body", "text", "message"]),
            timestamp: n(&v, &["timestamp", "time"]),
            incoming: b(&v, &["incoming", "is_incoming"]),
        })
        .filter(|x| !x.body.is_empty() || !x.contact.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct PhoneLinkMessage {
    pub device: String,
    pub contact: String,
    pub body: String,
    pub timestamp: u64,
    pub incoming: bool,
}

pub fn get_phone_link_calls() -> Vec<PhoneLinkCall> {
    let Some(items) = load(path("FORENSIC_PHONE_LINK_CALLS", "calls.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| PhoneLinkCall {
            device: s(&v, &["device", "device_name"]),
            contact: s(&v, &["contact", "contact_name"]),
            timestamp: n(&v, &["timestamp", "time"]),
            duration: n(&v, &["duration", "duration_seconds"]) as u32,
            call_type: s(&v, &["call_type", "type"]),
        })
        .filter(|x| x.timestamp > 0 || !x.contact.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct PhoneLinkCall {
    pub device: String,
    pub contact: String,
    pub timestamp: u64,
    pub duration: u32,
    pub call_type: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("phone_link").join(file))
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

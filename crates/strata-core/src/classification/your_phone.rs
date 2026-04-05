use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_yourphone_photos() -> Vec<YourPhonePhoto> {
    let Some(items) = load(path("FORENSIC_YOUR_PHONE_PHOTOS", "photos.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| YourPhonePhoto {
            device: s(&v, &["device", "device_name"]),
            file_name: s(&v, &["file_name", "name"]),
            taken: n(&v, &["taken", "taken_at"]),
            synced: n(&v, &["synced", "synced_at"]),
            local_path: s(&v, &["local_path", "path"]),
        })
        .filter(|x| !x.file_name.is_empty() || !x.local_path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct YourPhonePhoto {
    pub device: String,
    pub file_name: String,
    pub taken: u64,
    pub synced: u64,
    pub local_path: String,
}

pub fn get_yourphone_messages() -> Vec<YourPhoneMessage> {
    let Some(items) = load(path("FORENSIC_YOUR_PHONE_MESSAGES", "messages.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| YourPhoneMessage {
            device: s(&v, &["device", "device_name"]),
            conversation_id: s(&v, &["conversation_id", "thread_id"]),
            contact: s(&v, &["contact", "contact_name"]),
            body: s(&v, &["body", "text", "message"]),
            timestamp: n(&v, &["timestamp", "time"]),
            synced: b(&v, &["synced", "is_synced"]),
        })
        .filter(|x| !x.conversation_id.is_empty() || !x.body.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct YourPhoneMessage {
    pub device: String,
    pub conversation_id: String,
    pub contact: String,
    pub body: String,
    pub timestamp: u64,
    pub synced: bool,
}

pub fn get_yourphone_notifications() -> Vec<YourPhoneNotification> {
    let Some(items) = load(path(
        "FORENSIC_YOUR_PHONE_NOTIFICATIONS",
        "notifications.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| YourPhoneNotification {
            device: s(&v, &["device", "device_name"]),
            app_name: s(&v, &["app_name", "app"]),
            title: s(&v, &["title"]),
            text: s(&v, &["text", "body"]),
            timestamp: n(&v, &["timestamp", "time"]),
        })
        .filter(|x| !x.title.is_empty() || !x.text.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct YourPhoneNotification {
    pub device: String,
    pub app_name: String,
    pub title: String,
    pub text: String,
    pub timestamp: u64,
}

pub fn get_yourphone_screen() -> Vec<YourPhoneScreen> {
    let Some(items) = load(path("FORENSIC_YOUR_PHONE_SCREEN", "screen.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| YourPhoneScreen {
            device: s(&v, &["device", "device_name"]),
            captured: n(&v, &["captured", "timestamp"]),
            local_path: s(&v, &["local_path", "path"]),
            width: n(&v, &["width"]) as u32,
            height: n(&v, &["height"]) as u32,
        })
        .filter(|x| x.captured > 0 || !x.local_path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct YourPhoneScreen {
    pub device: String,
    pub captured: u64,
    pub local_path: String,
    pub width: u32,
    pub height: u32,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("your_phone").join(file))
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

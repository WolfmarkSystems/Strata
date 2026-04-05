use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_telegram_messages() -> Vec<TelegramMessage> {
    let path = data_path("FORENSIC_TELEGRAM_MESSAGES", "telegram_messages.json");
    let Some(items) = read_json(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| TelegramMessage {
            id: i(&v, &["id", "message_id"]),
            from_id: s(&v, &["from_id", "sender_id"]),
            text: s(&v, &["text", "message"]),
            date: n(&v, &["date", "timestamp"]),
            has_media: b(&v, &["has_media", "media"]),
        })
        .filter(|x| x.id != 0 || !x.text.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct TelegramMessage {
    pub id: i64,
    pub from_id: String,
    pub text: String,
    pub date: u64,
    pub has_media: bool,
}

pub fn get_telegram_contacts() -> Vec<TelegramContact> {
    let path = data_path("FORENSIC_TELEGRAM_CONTACTS", "telegram_contacts.json");
    let Some(items) = read_json(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| TelegramContact {
            id: i(&v, &["id", "contact_id"]),
            first_name: s(&v, &["first_name", "first"]),
            last_name: s(&v, &["last_name", "last"]),
            phone: s(&v, &["phone"]),
        })
        .filter(|x| x.id != 0 || !x.phone.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct TelegramContact {
    pub id: i64,
    pub first_name: String,
    pub last_name: String,
    pub phone: String,
}

pub fn get_telegram_channels() -> Vec<TelegramChannel> {
    let path = data_path("FORENSIC_TELEGRAM_CHANNELS", "telegram_channels.json");
    let Some(items) = read_json(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| TelegramChannel {
            id: i(&v, &["id", "channel_id"]),
            title: s(&v, &["title", "name"]),
            username: s(&v, &["username"]),
        })
        .filter(|x| x.id != 0 || !x.title.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct TelegramChannel {
    pub id: i64,
    pub title: String,
    pub username: String,
}

fn data_path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("chat").join(file))
}

fn read_json(path: PathBuf) -> Option<Vec<Value>> {
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
fn i(v: &Value, keys: &[&str]) -> i64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<i64>() {
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

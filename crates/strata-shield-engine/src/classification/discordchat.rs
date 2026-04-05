use std::env;
use std::path::{Path, PathBuf};

use serde_json::Value;

pub fn get_discord_messages() -> Vec<DiscordMessage> {
    parse_messages(&default_path(
        "FORENSIC_DISCORD_MESSAGES",
        "discord_messages.json",
    ))
}

#[derive(Debug, Clone, Default)]
pub struct DiscordMessage {
    pub id: String,
    pub channel_id: String,
    pub author: String,
    pub content: String,
    pub timestamp: u64,
    pub attachments: Vec<String>,
}

pub fn get_discord_dms() -> Vec<DiscordDm> {
    parse_dms(&default_path("FORENSIC_DISCORD_DMS", "discord_dms.json"))
}

#[derive(Debug, Clone, Default)]
pub struct DiscordDm {
    pub id: String,
    pub recipient: String,
    pub last_message: String,
    pub timestamp: u64,
}

pub fn get_discord_attachments() -> Vec<DiscordAttachment> {
    parse_attachments(&default_path(
        "FORENSIC_DISCORD_ATTACHMENTS",
        "discord_attachments.json",
    ))
}

#[derive(Debug, Clone, Default)]
pub struct DiscordAttachment {
    pub message_id: String,
    pub file_name: String,
    pub file_size: u64,
}

fn default_path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("chat").join(file))
}

fn parse_messages(path: &Path) -> Vec<DiscordMessage> {
    let Some(items) = load_json(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DiscordMessage {
            id: s(&v, &["id", "message_id"]),
            channel_id: s(&v, &["channel_id", "channel"]),
            author: s(&v, &["author", "sender", "user"]),
            content: s(&v, &["content", "message", "text"]),
            timestamp: n(&v, &["timestamp", "ts"]),
            attachments: sa(&v, &["attachments"]),
        })
        .filter(|row| !row.id.is_empty() || !row.content.is_empty())
        .collect()
}

fn parse_dms(path: &Path) -> Vec<DiscordDm> {
    let Some(items) = load_json(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DiscordDm {
            id: s(&v, &["id", "dm_id"]),
            recipient: s(&v, &["recipient", "user"]),
            last_message: s(&v, &["last_message", "text", "message"]),
            timestamp: n(&v, &["timestamp", "ts"]),
        })
        .filter(|row| !row.id.is_empty() || !row.recipient.is_empty())
        .collect()
}

fn parse_attachments(path: &Path) -> Vec<DiscordAttachment> {
    let Some(items) = load_json(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DiscordAttachment {
            message_id: s(&v, &["message_id", "id"]),
            file_name: s(&v, &["file_name", "name"]),
            file_size: n(&v, &["file_size", "size"]),
        })
        .filter(|row| !row.file_name.is_empty())
        .collect()
}

fn load_json(path: &Path) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
}

fn s(v: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(s) = v.get(*key).and_then(Value::as_str) {
            return s.to_string();
        }
    }
    String::new()
}

fn n(v: &Value, keys: &[&str]) -> u64 {
    for key in keys {
        if let Some(n) = v.get(*key).and_then(Value::as_u64) {
            return n;
        }
        if let Some(s) = v.get(*key).and_then(Value::as_str) {
            if let Ok(n) = s.parse::<u64>() {
                return n;
            }
        }
    }
    0
}

fn sa(v: &Value, keys: &[&str]) -> Vec<String> {
    for key in keys {
        if let Some(arr) = v.get(*key).and_then(Value::as_array) {
            return arr
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
        }
    }
    Vec::new()
}

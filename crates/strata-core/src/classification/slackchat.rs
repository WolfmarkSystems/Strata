use std::env;
use std::path::{Path, PathBuf};

use serde_json::Value;

pub fn get_slack_messages() -> Vec<SlackMessage> {
    let path = env::var("FORENSIC_SLACK_MESSAGES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("chat")
                .join("slack_messages.json")
        });
    parse_messages(&path)
}

#[derive(Debug, Clone, Default)]
pub struct SlackMessage {
    pub channel: String,
    pub user: String,
    pub text: String,
    pub timestamp: u64,
    pub attachments: Vec<String>,
}

pub fn get_slack_dms() -> Vec<SlackDm> {
    let path = env::var("FORENSIC_SLACK_DMS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("chat")
                .join("slack_dms.json")
        });
    parse_dms(&path)
}

#[derive(Debug, Clone, Default)]
pub struct SlackDm {
    pub user: String,
    pub last_message: String,
    pub timestamp: u64,
}

pub fn get_slack_files() -> Vec<SlackFile> {
    let path = env::var("FORENSIC_SLACK_FILES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("chat")
                .join("slack_files.json")
        });
    parse_files(&path)
}

#[derive(Debug, Clone, Default)]
pub struct SlackFile {
    pub name: String,
    pub size: u64,
    pub url: String,
    pub uploaded_by: String,
    pub timestamp: u64,
}

fn parse_messages(path: &Path) -> Vec<SlackMessage> {
    let Some(items) = load_json_array(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SlackMessage {
            channel: string_field(&v, &["channel", "channel_id"]),
            user: string_field(&v, &["user", "sender"]),
            text: string_field(&v, &["text", "message"]),
            timestamp: u64_field(&v, &["timestamp", "ts"]),
            attachments: string_array_field(&v, &["attachments"]),
        })
        .filter(|row| !row.text.is_empty() || !row.channel.is_empty())
        .collect()
}

fn parse_dms(path: &Path) -> Vec<SlackDm> {
    let Some(items) = load_json_array(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SlackDm {
            user: string_field(&v, &["user", "recipient"]),
            last_message: string_field(&v, &["last_message", "message", "text"]),
            timestamp: u64_field(&v, &["timestamp", "ts"]),
        })
        .filter(|row| !row.user.is_empty() || !row.last_message.is_empty())
        .collect()
}

fn parse_files(path: &Path) -> Vec<SlackFile> {
    let Some(items) = load_json_array(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SlackFile {
            name: string_field(&v, &["name", "file_name"]),
            size: u64_field(&v, &["size"]),
            url: string_field(&v, &["url", "url_private"]),
            uploaded_by: string_field(&v, &["uploaded_by", "user", "owner"]),
            timestamp: u64_field(&v, &["timestamp", "created"]),
        })
        .filter(|row| !row.name.is_empty() || !row.url.is_empty())
        .collect()
}

fn load_json_array(path: &Path) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
}

fn string_field(item: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(v) = item.get(*key).and_then(Value::as_str) {
            return v.to_string();
        }
    }
    String::new()
}

fn u64_field(item: &Value, keys: &[&str]) -> u64 {
    for key in keys {
        if let Some(v) = item.get(*key).and_then(Value::as_u64) {
            return v;
        }
        if let Some(s) = item.get(*key).and_then(Value::as_str) {
            if let Ok(v) = s.parse::<u64>() {
                return v;
            }
            if let Some((whole, _)) = s.split_once('.') {
                if let Ok(v) = whole.parse::<u64>() {
                    return v;
                }
            }
        }
    }
    0
}

fn string_array_field(item: &Value, keys: &[&str]) -> Vec<String> {
    for key in keys {
        if let Some(arr) = item.get(*key).and_then(Value::as_array) {
            return arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
    }
    Vec::new()
}

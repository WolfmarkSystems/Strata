use std::env;
use std::path::{Path, PathBuf};

use serde_json::Value;

pub fn get_teams_messages() -> Vec<TeamsMessage> {
    let path = env::var("FORENSIC_TEAMS_MESSAGES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("chat")
                .join("teams_messages.json")
        });
    parse_teams_messages(&path)
}

#[derive(Debug, Clone, Default)]
pub struct TeamsMessage {
    pub id: String,
    pub sender: String,
    pub content: String,
    pub timestamp: u64,
    pub conversation_id: String,
}

pub fn get_teams_calls() -> Vec<TeamsCall> {
    let path = env::var("FORENSIC_TEAMS_CALLS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("chat")
                .join("teams_calls.json")
        });
    parse_teams_calls(&path)
}

#[derive(Debug, Clone, Default)]
pub struct TeamsCall {
    pub id: String,
    pub caller: String,
    pub callee: String,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub call_type: String,
}

pub fn get_teams_files() -> Vec<TeamsFile> {
    let path = env::var("FORENSIC_TEAMS_FILES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("chat")
                .join("teams_files.json")
        });
    parse_teams_files(&path)
}

#[derive(Debug, Clone, Default)]
pub struct TeamsFile {
    pub file_name: String,
    pub file_path: String,
    pub shared_by: String,
    pub timestamp: u64,
}

fn parse_teams_messages(path: &Path) -> Vec<TeamsMessage> {
    let Some(items) = load_json_array(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|item| TeamsMessage {
            id: string_field(&item, &["id", "message_id"]),
            sender: string_field(&item, &["sender", "from"]),
            content: string_field(&item, &["content", "body", "text"]),
            timestamp: u64_field(&item, &["timestamp", "ts", "sent"]),
            conversation_id: string_field(&item, &["conversation_id", "thread_id", "chat_id"]),
        })
        .filter(|row| !row.id.is_empty() || !row.content.is_empty())
        .collect()
}

fn parse_teams_calls(path: &Path) -> Vec<TeamsCall> {
    let Some(items) = load_json_array(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|item| TeamsCall {
            id: string_field(&item, &["id", "call_id"]),
            caller: string_field(&item, &["caller", "from"]),
            callee: string_field(&item, &["callee", "to"]),
            start_time: u64_field(&item, &["start_time", "started", "timestamp"]),
            end_time: opt_u64_field(&item, &["end_time", "ended"]),
            call_type: string_field(&item, &["call_type", "type"]),
        })
        .filter(|row| !row.id.is_empty() || row.start_time > 0)
        .collect()
}

fn parse_teams_files(path: &Path) -> Vec<TeamsFile> {
    let Some(items) = load_json_array(path) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|item| TeamsFile {
            file_name: string_field(&item, &["file_name", "name"]),
            file_path: string_field(&item, &["file_path", "path"]),
            shared_by: string_field(&item, &["shared_by", "sender", "from"]),
            timestamp: u64_field(&item, &["timestamp", "shared"]),
        })
        .filter(|row| !row.file_name.is_empty() || !row.file_path.is_empty())
        .collect()
}

fn load_json_array(path: &Path) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let json: Value = serde_json::from_slice(&data).ok()?;
    json.as_array().cloned()
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
    opt_u64_field(item, keys).unwrap_or(0)
}

fn opt_u64_field(item: &Value, keys: &[&str]) -> Option<u64> {
    for key in keys {
        if let Some(n) = item.get(*key).and_then(Value::as_u64) {
            return Some(n);
        }
        if let Some(s) = item.get(*key).and_then(Value::as_str) {
            if let Ok(n) = s.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

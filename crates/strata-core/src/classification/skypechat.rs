use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_skype_messages() -> Vec<SkypeMessage> {
    let Some(items) = read_json(file_path("FORENSIC_SKYPE_MESSAGES", "skype_messages.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SkypeMessage {
            convo_id: strf(&v, &["convo_id", "conversation_id"]),
            author: strf(&v, &["author", "from"]),
            body: strf(&v, &["body", "text"]),
            timestamp: numf(&v, &["timestamp", "ts"]),
            msg_type: strf(&v, &["msg_type", "type"]),
        })
        .filter(|x| !x.body.is_empty() || !x.convo_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SkypeMessage {
    pub convo_id: String,
    pub author: String,
    pub body: String,
    pub timestamp: u64,
    pub msg_type: String,
}

pub fn get_skype_calls() -> Vec<SkypeCall> {
    let Some(items) = read_json(file_path("FORENSIC_SKYPE_CALLS", "skype_calls.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SkypeCall {
            host: strf(&v, &["host", "caller"]),
            participants: arrf(&v, &["participants", "members"]),
            start_time: numf(&v, &["start_time", "timestamp"]),
            duration: numf(&v, &["duration"]),
        })
        .filter(|x| !x.host.is_empty() || x.start_time > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SkypeCall {
    pub host: String,
    pub participants: Vec<String>,
    pub start_time: u64,
    pub duration: u64,
}

pub fn get_skype_transfers() -> Vec<SkypeTransfer> {
    let Some(items) = read_json(file_path(
        "FORENSIC_SKYPE_TRANSFERS",
        "skype_transfers.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SkypeTransfer {
            sender: strf(&v, &["sender", "from"]),
            receiver: strf(&v, &["receiver", "to"]),
            file_name: strf(&v, &["file_name", "name"]),
            file_size: numf(&v, &["file_size", "size"]),
            timestamp: numf(&v, &["timestamp", "ts"]),
        })
        .filter(|x| !x.file_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SkypeTransfer {
    pub sender: String,
    pub receiver: String,
    pub file_name: String,
    pub file_size: u64,
    pub timestamp: u64,
}

fn file_path(env_key: &str, file: &str) -> PathBuf {
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

fn strf(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}
fn numf(v: &Value, keys: &[&str]) -> u64 {
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
fn arrf(v: &Value, keys: &[&str]) -> Vec<String> {
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

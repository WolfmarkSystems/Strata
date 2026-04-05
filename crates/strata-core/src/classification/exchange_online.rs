use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_exchange_online_mailboxes() -> Vec<ExoMailbox> {
    let Some(items) = load(path("FORENSIC_EXO_MAILBOXES", "exo_mailboxes.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| ExoMailbox {
            email: s(&v, &["email", "primary_smtp"]),
            alias: s(&v, &["alias"]),
            created: n(&v, &["created"]),
            last_logon: n(&v, &["last_logon"]),
            item_count: n(&v, &["item_count"]) as u32,
            quota: n(&v, &["quota"]),
        })
        .filter(|x| !x.email.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ExoMailbox {
    pub email: String,
    pub alias: String,
    pub created: u64,
    pub last_logon: u64,
    pub item_count: u32,
    pub quota: u64,
}

pub fn get_exchange_online_messages() -> Vec<ExoMessage> {
    let Some(items) = load(path("FORENSIC_EXO_MESSAGES", "exo_messages.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| ExoMessage {
            mailbox: s(&v, &["mailbox"]),
            subject: s(&v, &["subject"]),
            sender: s(&v, &["sender", "from"]),
            recipients: sa(&v, &["recipients", "to"]),
            sent: n(&v, &["sent", "timestamp"]),
            has_attachments: b(&v, &["has_attachments"]),
        })
        .filter(|x| !x.mailbox.is_empty() || !x.subject.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ExoMessage {
    pub mailbox: String,
    pub subject: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub sent: u64,
    pub has_attachments: bool,
}

pub fn get_exo_push_notifications() -> Vec<ExoPushNotification> {
    let Some(items) = load(path("FORENSIC_EXO_PUSH", "exo_push_notifications.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| ExoPushNotification {
            device_id: s(&v, &["device_id"]),
            mailbox: s(&v, &["mailbox"]),
            notification_time: n(&v, &["notification_time", "timestamp"]),
            message_id: s(&v, &["message_id"]),
        })
        .filter(|x| !x.device_id.is_empty() || !x.mailbox.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ExoPushNotification {
    pub device_id: String,
    pub mailbox: String,
    pub notification_time: u64,
    pub message_id: String,
}

pub fn get_exo_folder_permissions() -> Vec<ExoFolderPermission> {
    let Some(items) = load(path(
        "FORENSIC_EXO_FOLDER_PERMS",
        "exo_folder_permissions.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| ExoFolderPermission {
            mailbox: s(&v, &["mailbox"]),
            folder: s(&v, &["folder"]),
            user: s(&v, &["user"]),
            permissions: sa(&v, &["permissions"]),
        })
        .filter(|x| !x.mailbox.is_empty() || !x.folder.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ExoFolderPermission {
    pub mailbox: String,
    pub folder: String,
    pub user: String,
    pub permissions: Vec<String>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key).map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from("artifacts")
            .join("exchange_online")
            .join(file)
    })
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

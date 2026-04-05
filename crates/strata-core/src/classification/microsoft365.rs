use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_onedrive_sync() -> Vec<OneDriveSync> {
    let Some(items) = load(path("FORENSIC_M365_ONEDRIVE_SYNC", "onedrive_sync.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| OneDriveSync {
            local_path: s(&v, &["local_path"]),
            cloud_path: s(&v, &["cloud_path"]),
            sync_status: s(&v, &["sync_status", "status"]),
            last_synced: n(&v, &["last_synced", "timestamp"]),
        })
        .filter(|x| !x.local_path.is_empty() || !x.cloud_path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct OneDriveSync {
    pub local_path: String,
    pub cloud_path: String,
    pub sync_status: String,
    pub last_synced: u64,
}

pub fn get_sharepoint_files() -> Vec<SharePointFile> {
    let Some(items) = load(path(
        "FORENSIC_M365_SHAREPOINT_FILES",
        "sharepoint_files.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SharePointFile {
            site: s(&v, &["site"]),
            document_library: s(&v, &["document_library", "library"]),
            path: s(&v, &["path"]),
            modified: n(&v, &["modified", "timestamp"]),
            modified_by: s(&v, &["modified_by"]),
        })
        .filter(|x| !x.site.is_empty() || !x.path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SharePointFile {
    pub site: String,
    pub document_library: String,
    pub path: String,
    pub modified: u64,
    pub modified_by: String,
}

pub fn get_teams_meetings() -> Vec<TeamsMeeting> {
    let Some(items) = load(path("FORENSIC_M365_TEAMS_MEETINGS", "teams_meetings.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| TeamsMeeting {
            meeting_id: s(&v, &["meeting_id", "id"]),
            subject: s(&v, &["subject"]),
            organizer: s(&v, &["organizer"]),
            start_time: n(&v, &["start_time", "start"]),
            end_time: n(&v, &["end_time", "end"]),
            participants: sa(&v, &["participants"]),
        })
        .filter(|x| !x.meeting_id.is_empty() || !x.subject.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct TeamsMeeting {
    pub meeting_id: String,
    pub subject: String,
    pub organizer: String,
    pub start_time: u64,
    pub end_time: u64,
    pub participants: Vec<String>,
}

pub fn get_teams_calls() -> Vec<TeamsCall> {
    let Some(items) = load(path("FORENSIC_M365_TEAMS_CALLS", "teams_calls.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| TeamsCall {
            call_id: s(&v, &["call_id", "id"]),
            caller: s(&v, &["caller"]),
            participants: sa(&v, &["participants"]),
            start_time: n(&v, &["start_time", "start"]),
            duration: n(&v, &["duration"]),
            call_type: s(&v, &["call_type", "type"]),
        })
        .filter(|x| !x.call_id.is_empty() || !x.caller.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct TeamsCall {
    pub call_id: String,
    pub caller: String,
    pub participants: Vec<String>,
    pub start_time: u64,
    pub duration: u64,
    pub call_type: String,
}

pub fn get_teams_shares() -> Vec<TeamsShare> {
    let Some(items) = load(path("FORENSIC_M365_TEAMS_SHARES", "teams_shares.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| TeamsShare {
            message_id: s(&v, &["message_id", "id"]),
            shared_by: s(&v, &["shared_by", "sender"]),
            file_name: s(&v, &["file_name", "name"]),
            timestamp: n(&v, &["timestamp", "shared"]),
        })
        .filter(|x| !x.message_id.is_empty() || !x.file_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct TeamsShare {
    pub message_id: String,
    pub shared_by: String,
    pub file_name: String,
    pub timestamp: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("m365").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let json: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = json.as_array() {
        Some(items.clone())
    } else if json.is_object() {
        Some(vec![json])
    } else {
        None
    }
}

fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}

fn sa(v: &Value, keys: &[&str]) -> Vec<String> {
    for k in keys {
        if let Some(items) = v.get(*k).and_then(Value::as_array) {
            return items
                .iter()
                .filter_map(|x| x.as_str().map(ToString::to_string))
                .collect();
        }
    }
    Vec::new()
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

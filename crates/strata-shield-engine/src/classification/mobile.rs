use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct ITunesBackup {
    pub backup_path: String,
    pub device_name: String,
    pub device_id: String,
    pub backup_type: BackupType,
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub files: Vec<BackupFile>,
}

#[derive(Debug, Clone, Default)]
pub enum BackupType {
    #[default]
    Unknown,
    Full,
    Incremental,
    ICloud,
}

#[derive(Debug, Clone, Default)]
pub struct BackupFile {
    pub file_id: String,
    pub domain: String,
    pub path: String,
    pub file_type: String,
    pub size: u64,
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub is_encrypted: bool,
    pub protection_class: i32,
}

#[derive(Debug, Clone, Default)]
pub struct Contact {
    pub record_id: String,
    pub first_name: String,
    pub last_name: String,
    pub phone_numbers: Vec<String>,
    pub email_addresses: Vec<String>,
    pub addresses: Vec<String>,
    pub organization: String,
    pub notes: String,
    pub photo_path: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SmsMessage {
    pub message_id: String,
    pub conversation_id: String,
    pub sender: String,
    pub recipient: String,
    pub message_text: String,
    pub timestamp: u64,
    pub is_read: bool,
    pub is_delivered: bool,
    pub service: String,
}

#[derive(Debug, Clone, Default)]
pub struct CallLog {
    pub call_id: String,
    pub phone_number: String,
    pub caller_name: String,
    pub timestamp: u64,
    pub duration: u32,
    pub call_type: CallType,
    pub is_read: bool,
}

#[derive(Debug, Clone, Default)]
pub enum CallType {
    #[default]
    Unknown,
    Incoming,
    Outgoing,
    Missed,
    Voicemail,
}

#[derive(Debug, Clone, Default)]
pub struct CalendarEvent {
    pub event_id: String,
    pub title: String,
    pub start_time: u64,
    pub end_time: u64,
    pub location: String,
    pub notes: String,
    pub attendees: Vec<String>,
    pub calendar_name: String,
    pub is_all_day: bool,
}

pub fn get_itunes_backup_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\Users\Default\Apple\MobileSync\Backup"),
        PathBuf::from(r"C:\Users\Default\AppData\Roaming\Apple Computer\MobileSync\Backup"),
    ]
}

pub fn parse_itunes_backup(backup_path: &Path) -> Result<ITunesBackup, ForensicError> {
    let metadata_path = env::var("FORENSIC_ITUNES_BACKUP_METADATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| backup_path.join("backup_metadata.json"));
    let metadata = load_value(&metadata_path);
    let files = metadata
        .as_ref()
        .and_then(|v| v.get("files"))
        .and_then(Value::as_array)
        .map(|xs| xs.iter().map(parse_backup_file).collect())
        .unwrap_or_default();
    let backup = ITunesBackup {
        backup_path: backup_path.to_string_lossy().to_string(),
        device_name: metadata
            .as_ref()
            .map(|v| s(v, &["device_name", "name"]))
            .unwrap_or_default(),
        device_id: metadata
            .as_ref()
            .map(|v| s(v, &["device_id", "id"]))
            .unwrap_or_default(),
        backup_type: metadata
            .as_ref()
            .map(|v| backup_type_enum(s(v, &["backup_type", "type"])))
            .unwrap_or(BackupType::Unknown),
        created: metadata
            .as_ref()
            .and_then(|v| opt_n(v, &["created", "created_time"])),
        modified: metadata
            .as_ref()
            .and_then(|v| opt_n(v, &["modified", "modified_time"])),
        files,
    };
    Ok(backup)
}

pub fn get_backup_manifest(
    _backup_path: &Path,
) -> Result<HashMap<String, BackupFile>, ForensicError> {
    Ok(HashMap::new())
}

pub fn decrypt_backup_file(
    backup_path: &Path,
    file_id: &str,
    _password: Option<&str>,
) -> Result<Vec<u8>, ForensicError> {
    let path = backup_path.join(format!("{file_id}.bin"));
    Ok(
        super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
            .unwrap_or_default(),
    )
}

pub fn extract_contacts(backup_path: &Path) -> Result<Vec<Contact>, ForensicError> {
    let Some(items) = load_array(resolve_path(
        backup_path,
        "FORENSIC_MOBILE_CONTACTS",
        "contacts.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| Contact {
            record_id: s(&v, &["record_id", "id"]),
            first_name: s(&v, &["first_name"]),
            last_name: s(&v, &["last_name"]),
            phone_numbers: str_vec(&v, &["phone_numbers", "phones"]),
            email_addresses: str_vec(&v, &["email_addresses", "emails"]),
            addresses: str_vec(&v, &["addresses"]),
            organization: s(&v, &["organization", "company"]),
            notes: s(&v, &["notes"]),
            photo_path: s_opt(&v, &["photo_path"]),
        })
        .filter(|x| !x.record_id.is_empty() || !x.first_name.is_empty() || !x.last_name.is_empty())
        .collect())
}

pub fn extract_sms(backup_path: &Path) -> Result<Vec<SmsMessage>, ForensicError> {
    let Some(items) = load_array(resolve_path(backup_path, "FORENSIC_MOBILE_SMS", "sms.json"))
    else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| SmsMessage {
            message_id: s(&v, &["message_id", "id"]),
            conversation_id: s(&v, &["conversation_id", "thread_id"]),
            sender: s(&v, &["sender", "from"]),
            recipient: s(&v, &["recipient", "to"]),
            message_text: s(&v, &["message_text", "body"]),
            timestamp: n(&v, &["timestamp", "time"]),
            is_read: b(&v, &["is_read", "read"]),
            is_delivered: b(&v, &["is_delivered", "delivered"]),
            service: s(&v, &["service"]),
        })
        .filter(|x| !x.message_id.is_empty() || x.timestamp > 0 || !x.message_text.is_empty())
        .collect())
}

pub fn extract_call_logs(backup_path: &Path) -> Result<Vec<CallLog>, ForensicError> {
    let Some(items) = load_array(resolve_path(
        backup_path,
        "FORENSIC_MOBILE_CALL_LOGS",
        "call_logs.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| CallLog {
            call_id: s(&v, &["call_id", "id"]),
            phone_number: s(&v, &["phone_number", "number"]),
            caller_name: s(&v, &["caller_name", "name"]),
            timestamp: n(&v, &["timestamp", "time"]),
            duration: n(&v, &["duration", "duration_seconds"]) as u32,
            call_type: call_type_enum(s(&v, &["call_type", "type"])),
            is_read: b(&v, &["is_read", "read"]),
        })
        .filter(|x| !x.call_id.is_empty() || x.timestamp > 0)
        .collect())
}

pub fn extract_calendar(backup_path: &Path) -> Result<Vec<CalendarEvent>, ForensicError> {
    let Some(items) = load_array(resolve_path(
        backup_path,
        "FORENSIC_MOBILE_CALENDAR",
        "calendar.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| CalendarEvent {
            event_id: s(&v, &["event_id", "id"]),
            title: s(&v, &["title"]),
            start_time: n(&v, &["start_time", "start"]),
            end_time: n(&v, &["end_time", "end"]),
            location: s(&v, &["location"]),
            notes: s(&v, &["notes"]),
            attendees: str_vec(&v, &["attendees"]),
            calendar_name: s(&v, &["calendar_name", "calendar"]),
            is_all_day: b(&v, &["is_all_day", "all_day"]),
        })
        .filter(|x| !x.event_id.is_empty() || !x.title.is_empty() || x.start_time > 0)
        .collect())
}

pub fn extract_browser_history(backup_path: &Path) -> Result<Vec<BrowserHistory>, ForensicError> {
    let Some(items) = load_array(resolve_path(
        backup_path,
        "FORENSIC_MOBILE_BROWSER_HISTORY",
        "browser_history.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| BrowserHistory {
            url: s(&v, &["url"]),
            title: s(&v, &["title"]),
            visit_time: n(&v, &["visit_time", "timestamp"]),
            visit_count: n(&v, &["visit_count", "count"]) as u32,
        })
        .filter(|x| !x.url.is_empty() || x.visit_time > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct BrowserHistory {
    pub url: String,
    pub title: String,
    pub visit_time: u64,
    pub visit_count: u32,
}

pub fn extract_location_history(backup_path: &Path) -> Result<Vec<LocationEntry>, ForensicError> {
    let Some(items) = load_array(resolve_path(
        backup_path,
        "FORENSIC_MOBILE_LOCATION_HISTORY",
        "location_history.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| LocationEntry {
            latitude: f(&v, &["latitude", "lat"]),
            longitude: f(&v, &["longitude", "lon", "lng"]),
            timestamp: n(&v, &["timestamp", "time"]),
            horizontal_accuracy: f(&v, &["horizontal_accuracy", "accuracy"]),
        })
        .filter(|x| x.timestamp > 0 || (x.latitude != 0.0 && x.longitude != 0.0))
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct LocationEntry {
    pub latitude: f64,
    pub longitude: f64,
    pub timestamp: u64,
    pub horizontal_accuracy: f64,
}

pub fn extract_installed_apps(backup_path: &Path) -> Result<Vec<InstalledApp>, ForensicError> {
    let Some(items) = load_array(resolve_path(
        backup_path,
        "FORENSIC_MOBILE_INSTALLED_APPS",
        "installed_apps.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| InstalledApp {
            bundle_id: s(&v, &["bundle_id", "id"]),
            name: s(&v, &["name"]),
            version: s(&v, &["version"]),
            install_time: n(&v, &["install_time", "installed_at"]),
            app_path: s(&v, &["app_path", "path"]),
        })
        .filter(|x| !x.bundle_id.is_empty() || !x.name.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct InstalledApp {
    pub bundle_id: String,
    pub name: String,
    pub version: String,
    pub install_time: u64,
    pub app_path: String,
}

pub fn extract_voicemails(backup_path: &Path) -> Result<Vec<Voicemail>, ForensicError> {
    let Some(items) = load_array(resolve_path(
        backup_path,
        "FORENSIC_MOBILE_VOICEMAILS",
        "voicemails.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| Voicemail {
            voicemail_id: s(&v, &["voicemail_id", "id"]),
            sender: s(&v, &["sender", "from"]),
            duration: n(&v, &["duration", "duration_seconds"]) as u32,
            timestamp: n(&v, &["timestamp", "time"]),
            transcript: s(&v, &["transcript"]),
            audio_path: s_opt(&v, &["audio_path", "path"]),
        })
        .filter(|x| !x.voicemail_id.is_empty() || x.timestamp > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct Voicemail {
    pub voicemail_id: String,
    pub sender: String,
    pub duration: u32,
    pub timestamp: u64,
    pub transcript: String,
    pub audio_path: Option<String>,
}

pub fn get_device_info(_backup_path: &Path) -> Result<HashMap<String, String>, ForensicError> {
    let mut info = HashMap::new();
    info.insert("device_name".to_string(), "".to_string());
    info.insert("device_id".to_string(), "".to_string());
    info.insert("ios_version".to_string(), "".to_string());
    info.insert("backup_version".to_string(), "".to_string());
    info.insert("is_encrypted".to_string(), "false".to_string());
    Ok(info)
}

fn parse_backup_file(v: &Value) -> BackupFile {
    BackupFile {
        file_id: s(v, &["file_id", "id"]),
        domain: s(v, &["domain"]),
        path: s(v, &["path"]),
        file_type: s(v, &["file_type", "type"]),
        size: n(v, &["size", "size_bytes"]),
        created: opt_n(v, &["created", "created_time"]),
        modified: opt_n(v, &["modified", "modified_time"]),
        is_encrypted: b(v, &["is_encrypted", "encrypted"]),
        protection_class: n(v, &["protection_class"]) as i32,
    }
}

fn backup_type_enum(value: String) -> BackupType {
    match value.to_ascii_lowercase().as_str() {
        "full" => BackupType::Full,
        "incremental" => BackupType::Incremental,
        "icloud" | "i_cloud" => BackupType::ICloud,
        _ => BackupType::Unknown,
    }
}

fn call_type_enum(value: String) -> CallType {
    match value.to_ascii_lowercase().as_str() {
        "incoming" => CallType::Incoming,
        "outgoing" => CallType::Outgoing,
        "missed" => CallType::Missed,
        "voicemail" => CallType::Voicemail,
        _ => CallType::Unknown,
    }
}

fn resolve_path(backup_path: &Path, env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| backup_path.join(file))
}

fn load_array(path: PathBuf) -> Option<Vec<Value>> {
    let v = load_value(&path)?;
    if let Some(items) = v.as_array() {
        Some(items.clone())
    } else if v.is_object() {
        v.get("items")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| v.get("results").and_then(Value::as_array).cloned())
            .or_else(|| Some(vec![v]))
    } else {
        None
    }
}

fn load_value(path: &Path) -> Option<Value> {
    let data = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data).ok()
}

fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}

fn s_opt(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return Some(x.to_string());
        }
    }
    None
}

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}

fn n(v: &Value, keys: &[&str]) -> u64 {
    opt_n(v, keys).unwrap_or(0)
}

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return Some(x as u64);
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

fn f(v: &Value, keys: &[&str]) -> f64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_f64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<f64>() {
                return n;
            }
        }
    }
    0.0
}

fn str_vec(v: &Value, keys: &[&str]) -> Vec<String> {
    for k in keys {
        if let Some(items) = v.get(*k).and_then(Value::as_array) {
            return items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect();
        }
    }
    Vec::new()
}

use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_bitlocker_protectors() -> Vec<BitLockerProtector> {
    let Some(items) = load(path(
        "FORENSIC_BITLOCKER_PROTECTORS",
        "bitlocker_protectors.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| BitLockerProtector {
            volume: s(&v, &["volume", "drive_letter"]),
            protector_type: s(&v, &["protector_type", "type"]),
            protector_id: s(&v, &["protector_id", "id"]),
            created: n(&v, &["created", "timestamp"]),
            key_derived: b(&v, &["key_derived"]),
        })
        .filter(|x| !x.volume.is_empty() || !x.protector_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct BitLockerProtector {
    pub volume: String,
    pub protector_type: String,
    pub protector_id: String,
    pub created: u64,
    pub key_derived: bool,
}

pub fn get_bitlocker_recovery() -> Vec<BitLockerRecovery> {
    let Some(items) = load(path(
        "FORENSIC_BITLOCKER_RECOVERY",
        "bitlocker_recovery.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| BitLockerRecovery {
            volume: s(&v, &["volume", "drive_letter"]),
            recovery_id: s(&v, &["recovery_id", "id"]),
            recovery_password: s(&v, &["recovery_password", "password"]),
            created: n(&v, &["created", "timestamp"]),
            reset_count: n(&v, &["reset_count"]) as u32,
        })
        .filter(|x| !x.volume.is_empty() || !x.recovery_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct BitLockerRecovery {
    pub volume: String,
    pub recovery_id: String,
    pub recovery_password: String,
    pub created: u64,
    pub reset_count: u32,
}

pub fn get_bitlocker_keys() -> Vec<BitLockerKey> {
    let Some(items) = load(path("FORENSIC_BITLOCKER_KEYS", "bitlocker_keys.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| BitLockerKey {
            volume: s(&v, &["volume", "drive_letter"]),
            key_type: s(&v, &["key_type", "type"]),
            key_identifier: s(&v, &["key_identifier", "id"]),
            created: n(&v, &["created", "timestamp"]),
            protector_type: s(&v, &["protector_type"]),
        })
        .filter(|x| !x.volume.is_empty() || !x.key_identifier.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct BitLockerKey {
    pub volume: String,
    pub key_type: String,
    pub key_identifier: String,
    pub created: u64,
    pub protector_type: String,
}

pub fn get_bitlocker_events() -> Vec<BitLockerEvent> {
    let Some(items) = load(path("FORENSIC_BITLOCKER_EVENTS", "bitlocker_events.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| BitLockerEvent {
            timestamp: n(&v, &["timestamp", "time"]),
            event_id: n(&v, &["event_id", "id"]) as u32,
            volume: s(&v, &["volume", "drive_letter"]),
            action: s(&v, &["action"]),
            result: s(&v, &["result", "status"]),
        })
        .filter(|x| x.timestamp > 0 || x.event_id > 0 || !x.volume.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct BitLockerEvent {
    pub timestamp: u64,
    pub event_id: u32,
    pub volume: String,
    pub action: String,
    pub result: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("encryption").join(file))
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

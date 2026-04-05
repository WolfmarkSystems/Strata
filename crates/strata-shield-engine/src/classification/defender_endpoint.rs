use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_defender_alerts() -> Vec<DefenderAlert> {
    let Some(items) = load(path("FORENSIC_DEFENDER_ALERTS", "alerts.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DefenderAlert {
            alert_id: s(&v, &["alert_id", "id"]),
            title: s(&v, &["title"]),
            severity: s(&v, &["severity"]),
            category: s(&v, &["category"]),
            detected: n(&v, &["detected", "detected_at"]),
            status: s(&v, &["status"]),
            machine_name: s(&v, &["machine_name", "device_name"]),
        })
        .filter(|x| !x.alert_id.is_empty() || !x.title.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct DefenderAlert {
    pub alert_id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
    pub detected: u64,
    pub status: String,
    pub machine_name: String,
}

pub fn get_defender_indicators() -> Vec<DefenderIndicator> {
    let Some(items) = load(path("FORENSIC_DEFENDER_INDICATORS", "indicators.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DefenderIndicator {
            indicator_type: s(&v, &["indicator_type", "type"]),
            value: s(&v, &["value"]),
            action: s(&v, &["action"]),
            created: n(&v, &["created", "created_at"]),
            expiration: n(&v, &["expiration", "expires_at"]),
        })
        .filter(|x| !x.indicator_type.is_empty() || !x.value.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct DefenderIndicator {
    pub indicator_type: String,
    pub value: String,
    pub action: String,
    pub created: u64,
    pub expiration: u64,
}

pub fn get_defender_file_profiles() -> Vec<DefenderFileProfile> {
    let Some(items) = load(path(
        "FORENSIC_DEFENDER_FILE_PROFILES",
        "file_profiles.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DefenderFileProfile {
            sha1: s(&v, &["sha1", "hash"]),
            detection_name: s(&v, &["detection_name", "name"]),
            first_seen: n(&v, &["first_seen"]),
            prevalence: n(&v, &["prevalence"]) as u32,
            is_malicious: b(&v, &["is_malicious", "malicious"]),
        })
        .filter(|x| !x.sha1.is_empty() || !x.detection_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct DefenderFileProfile {
    pub sha1: String,
    pub detection_name: String,
    pub first_seen: u64,
    pub prevalence: u32,
    pub is_malicious: bool,
}

pub fn get_defender_machine_actions() -> Vec<DefenderMachineAction> {
    let Some(items) = load(path(
        "FORENSIC_DEFENDER_MACHINE_ACTIONS",
        "machine_actions.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DefenderMachineAction {
            action_id: s(&v, &["action_id", "id"]),
            machine_id: s(&v, &["machine_id", "device_id"]),
            action_type: s(&v, &["action_type", "type"]),
            requested: n(&v, &["requested", "requested_at"]),
            completed: opt_n(&v, &["completed", "completed_at"]),
            status: s(&v, &["status"]),
        })
        .filter(|x| !x.action_id.is_empty() || !x.action_type.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct DefenderMachineAction {
    pub action_id: String,
    pub machine_id: String,
    pub action_type: String,
    pub requested: u64,
    pub completed: Option<u64>,
    pub status: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key).map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from("artifacts")
            .join("defender_endpoint")
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
    opt_n(v, keys).unwrap_or(0)
}

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return Some(n);
            }
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

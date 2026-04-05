use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_azuread_devices() -> Vec<AzureAdDevice> {
    let Some(items) = load(path("FORENSIC_AZUREAD_DEVICES", "azuread_devices.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AzureAdDevice {
            device_id: s(&v, &["device_id", "id"]),
            display_name: s(&v, &["display_name", "name"]),
            operating_system: s(&v, &["operating_system", "os"]),
            registered: n(&v, &["registered", "created"]),
            last_logon: n(&v, &["last_logon"]),
            compliant: b(&v, &["compliant"]),
            join_type: s(&v, &["join_type", "trust_type"]),
        })
        .filter(|x| !x.device_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AzureAdDevice {
    pub device_id: String,
    pub display_name: String,
    pub operating_system: String,
    pub registered: u64,
    pub last_logon: u64,
    pub compliant: bool,
    pub join_type: String,
}

pub fn get_azuread_registrations() -> Vec<AzureAdRegistration> {
    let Some(items) = load(path(
        "FORENSIC_AZUREAD_REGISTRATIONS",
        "azuread_registrations.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AzureAdRegistration {
            user: s(&v, &["user", "upn"]),
            device_id: s(&v, &["device_id"]),
            registered: n(&v, &["registered"]),
            auth_methods: sa(&v, &["auth_methods", "mfa"]),
        })
        .filter(|x| !x.user.is_empty() || !x.device_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AzureAdRegistration {
    pub user: String,
    pub device_id: String,
    pub registered: u64,
    pub auth_methods: Vec<String>,
}

pub fn get_mdm_enrollments() -> Vec<MdmEnrollment> {
    let Some(items) = load(path("FORENSIC_MDM_ENROLLMENTS", "mdm_enrollments.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| MdmEnrollment {
            device_id: s(&v, &["device_id"]),
            mdm: s(&v, &["mdm", "provider"]),
            enrolled: n(&v, &["enrolled"]),
            last_checkin: n(&v, &["last_checkin"]),
            status: s(&v, &["status"]),
        })
        .filter(|x| !x.device_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct MdmEnrollment {
    pub device_id: String,
    pub mdm: String,
    pub enrolled: u64,
    pub last_checkin: u64,
    pub status: String,
}

pub fn get_device_compliance() -> Vec<DeviceCompliance> {
    let Some(items) = load(path("FORENSIC_DEVICE_COMPLIANCE", "device_compliance.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DeviceCompliance {
            device_id: s(&v, &["device_id"]),
            compliant: b(&v, &["compliant"]),
            policy: s(&v, &["policy"]),
            checked: n(&v, &["checked", "timestamp"]),
            violations: sa(&v, &["violations"]),
        })
        .filter(|x| !x.device_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct DeviceCompliance {
    pub device_id: String,
    pub compliant: bool,
    pub policy: String,
    pub checked: u64,
    pub violations: Vec<String>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("azure_ad").join(file))
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

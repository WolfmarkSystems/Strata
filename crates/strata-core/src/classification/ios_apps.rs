use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_ios_apps() -> Vec<IosApp> {
    let Some(items) = load(path("FORENSIC_IOS_APPS", "ios_apps.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| IosApp {
            bundle_id: s(&v, &["bundle_id", "bundle"]),
            app_name: s(&v, &["app_name", "name"]),
            version: s(&v, &["version"]),
            install_date: n(&v, &["install_date", "installed"]),
            permissions: sa(&v, &["permissions"]),
        })
        .filter(|x| !x.bundle_id.is_empty() || !x.app_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct IosApp {
    pub bundle_id: String,
    pub app_name: String,
    pub version: String,
    pub install_date: u64,
    pub permissions: Vec<String>,
}

pub fn get_ios_sms() -> Vec<IosSms> {
    let Some(items) = load(path("FORENSIC_IOS_SMS", "ios_sms.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| IosSms {
            handle: s(&v, &["handle", "address"]),
            text: s(&v, &["text", "body"]),
            date: ni(&v, &["date", "timestamp"]),
            is_from_me: b(&v, &["is_from_me"]),
            cache_has_attachments: b(&v, &["cache_has_attachments", "has_attachments"]),
        })
        .filter(|x| !x.handle.is_empty() || !x.text.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct IosSms {
    pub handle: String,
    pub text: String,
    pub date: i64,
    pub is_from_me: bool,
    pub cache_has_attachments: bool,
}

pub fn get_ios_calls() -> Vec<IosCall> {
    let Some(items) = load(path("FORENSIC_IOS_CALLS", "ios_calls.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| IosCall {
            address: s(&v, &["address", "number"]),
            duration: ni(&v, &["duration"]),
            date: ni(&v, &["date", "timestamp"]),
            call_type: ni(&v, &["call_type", "type"]) as i32,
        })
        .filter(|x| !x.address.is_empty() || x.date > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct IosCall {
    pub address: String,
    pub duration: i64,
    pub date: i64,
    pub call_type: i32,
}

pub fn get_ios_contacts() -> Vec<IosContact> {
    let Some(items) = load(path("FORENSIC_IOS_CONTACTS", "ios_contacts.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| IosContact {
            name: s(&v, &["name"]),
            phones: sa(&v, &["phones"]),
            emails: sa(&v, &["emails"]),
        })
        .filter(|x| !x.name.is_empty() || !x.phones.is_empty() || !x.emails.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct IosContact {
    pub name: String,
    pub phones: Vec<String>,
    pub emails: Vec<String>,
}

pub fn get_ios_location() -> Vec<IosLocation> {
    let Some(items) = load(path("FORENSIC_IOS_LOCATION", "ios_location.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| IosLocation {
            latitude: f(&v, &["latitude", "lat"]),
            longitude: f(&v, &["longitude", "lon"]),
            timestamp: ni(&v, &["timestamp", "date"]),
            horizontal_accuracy: f(&v, &["horizontal_accuracy", "accuracy"]),
        })
        .filter(|x| x.timestamp > 0 || x.latitude != 0.0 || x.longitude != 0.0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct IosLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub timestamp: i64,
    pub horizontal_accuracy: f64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("ios").join(file))
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

fn ni(v: &Value, keys: &[&str]) -> i64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            if let Ok(n) = i64::try_from(x) {
                return n;
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<i64>() {
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

pub fn get_ios_health() -> Vec<IosHealthData> {
    let Some(items) = load(path("FORENSIC_IOS_HEALTH", "ios_health.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| IosHealthData {
            data_type: s(&v, &["type", "dataType"]),
            value: f(&v, &["value", "amount"]),
            unit: s(&v, &["unit"]),
            start_date: ni(&v, &["startDate", "start_date"]),
            end_date: ni(&v, &["endDate", "end_date"]),
        })
        .filter(|x| !x.data_type.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct IosHealthData {
    pub data_type: String,
    pub value: f64,
    pub unit: String,
    pub start_date: i64,
    pub end_date: i64,
}

pub fn get_ios_location_fused() -> Vec<IosLocationData> {
    let Some(items) = load(path("FORENSIC_IOS_LOCATION", "ios_location.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| IosLocationData {
            latitude: f(&v, &["latitude", "lat"]),
            longitude: f(&v, &["longitude", "lon"]),
            timestamp: ni(&v, &["timestamp", "date"]),
            horizontal_accuracy: f(&v, &["horizontalAccuracy", "accuracy"]),
        })
        .filter(|x| x.timestamp > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct IosLocationData {
    pub latitude: f64,
    pub longitude: f64,
    pub timestamp: i64,
    pub horizontal_accuracy: f64,
}

pub fn get_ios_screentime() -> Vec<IosScreenTime> {
    let Some(items) = load(path("FORENSIC_IOS_SCREENTIME", "ios_screentime.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| IosScreenTime {
            app_name: s(&v, &["appName", "app_name", "bundleId"]),
            usage_minutes: ni(&v, &["usageMinutes", "usage_minutes", "minutes"]),
            date: ni(&v, &["date"]),
        })
        .filter(|x| !x.app_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct IosScreenTime {
    pub app_name: String,
    pub usage_minutes: i64,
    pub date: i64,
}

pub fn get_ios_wallet() -> Vec<IosWalletPass> {
    let Some(items) = load(path("FORENSIC_IOS_WALLET", "ios_wallet.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| IosWalletPass {
            pass_type: s(&v, &["passType", "type"]),
            title: s(&v, &["title", "description"]),
            barcode: s(&v, &["barcode", "barcodeValue"]),
            created: ni(&v, &["created", "dateAdded"]),
        })
        .filter(|x| !x.pass_type.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct IosWalletPass {
    pub pass_type: String,
    pub title: String,
    pub barcode: String,
    pub created: i64,
}

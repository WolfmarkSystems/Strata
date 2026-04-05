use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_android_apps() -> Vec<AndroidApp> {
    let Some(items) = load(path("FORENSIC_ANDROID_APPS", "android_apps.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AndroidApp {
            package_name: s(&v, &["package_name", "package"]),
            app_name: s(&v, &["app_name", "name"]),
            version: s(&v, &["version"]),
            install_time: n(&v, &["install_time", "installed"]),
            update_time: n(&v, &["update_time", "updated"]),
            permissions: sa(&v, &["permissions"]),
        })
        .filter(|x| !x.package_name.is_empty() || !x.app_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AndroidApp {
    pub package_name: String,
    pub app_name: String,
    pub version: String,
    pub install_time: u64,
    pub update_time: u64,
    pub permissions: Vec<String>,
}

pub fn get_android_sms() -> Vec<AndroidSms> {
    let Some(items) = load(path("FORENSIC_ANDROID_SMS", "android_sms.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AndroidSms {
            address: s(&v, &["address", "phone"]),
            body: s(&v, &["body", "text"]),
            date: ni(&v, &["date", "timestamp"]),
            read: b(&v, &["read", "is_read"]),
            thread_id: ni(&v, &["thread_id"]),
        })
        .filter(|x| !x.address.is_empty() || !x.body.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AndroidSms {
    pub address: String,
    pub body: String,
    pub date: i64,
    pub read: bool,
    pub thread_id: i64,
}

pub fn get_android_calls() -> Vec<AndroidCall> {
    let Some(items) = load(path("FORENSIC_ANDROID_CALLS", "android_calls.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AndroidCall {
            number: s(&v, &["number", "phone"]),
            duration: ni(&v, &["duration"]),
            date: ni(&v, &["date", "timestamp"]),
            call_type: ni(&v, &["call_type", "type"]) as i32,
        })
        .filter(|x| !x.number.is_empty() || x.date > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AndroidCall {
    pub number: String,
    pub duration: i64,
    pub date: i64,
    pub call_type: i32,
}

pub fn get_android_contacts() -> Vec<AndroidContact> {
    let Some(items) = load(path("FORENSIC_ANDROID_CONTACTS", "android_contacts.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AndroidContact {
            name: s(&v, &["name"]),
            phones: sa(&v, &["phones"]),
            emails: sa(&v, &["emails"]),
        })
        .filter(|x| !x.name.is_empty() || !x.phones.is_empty() || !x.emails.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AndroidContact {
    pub name: String,
    pub phones: Vec<String>,
    pub emails: Vec<String>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("android").join(file))
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

use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_office_recent() -> Vec<OfficeRecent> {
    let Some(items) = load(path("FORENSIC_OFFICE_RECENT", "office_recent.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| OfficeRecent {
            file_path: s(&v, &["file_path", "path"]),
            file_type: s(&v, &["file_type", "type"]),
            last_opened: n(&v, &["last_opened", "timestamp"]),
            application: s(&v, &["application", "app"]),
        })
        .filter(|x| !x.file_path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct OfficeRecent {
    pub file_path: String,
    pub file_type: String,
    pub last_opened: u64,
    pub application: String,
}

pub fn get_office_temp_files() -> Vec<OfficeTempFile> {
    let Some(items) = load(path("FORENSIC_OFFICE_TEMP", "office_temp_files.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| OfficeTempFile {
            original_path: opt_s(&v, &["original_path", "source_path"]),
            temp_path: s(&v, &["temp_path", "path"]),
            created: n(&v, &["created"]),
            modified: n(&v, &["modified"]),
        })
        .filter(|x| !x.temp_path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct OfficeTempFile {
    pub original_path: Option<String>,
    pub temp_path: String,
    pub created: u64,
    pub modified: u64,
}

pub fn get_office_coauthoring() -> Vec<OfficeCoauthor> {
    let Some(items) = load(path("FORENSIC_OFFICE_COAUTHOR", "office_coauthoring.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| OfficeCoauthor {
            document_path: s(&v, &["document_path", "path"]),
            coauthor: s(&v, &["coauthor", "user"]),
            last_edit: n(&v, &["last_edit", "timestamp"]),
            edit_count: n(&v, &["edit_count", "count"]) as u32,
        })
        .filter(|x| !x.document_path.is_empty() || !x.coauthor.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct OfficeCoauthor {
    pub document_path: String,
    pub coauthor: String,
    pub last_edit: u64,
    pub edit_count: u32,
}

pub fn get_office_accounts() -> Vec<OfficeAccount> {
    let Some(items) = load(path(
        "FORENSIC_OFFICE_ACCOUNTS",
        "office_accounts_deep.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| OfficeAccount {
            email: s(&v, &["email"]),
            account_type: s(&v, &["account_type", "type"]),
            last_used: n(&v, &["last_used", "timestamp"]),
            subscription: s(&v, &["subscription", "license"]),
        })
        .filter(|x| !x.email.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct OfficeAccount {
    pub email: String,
    pub account_type: String,
    pub last_used: u64,
    pub subscription: String,
}

pub fn get_office_licenses() -> Vec<OfficeLicense> {
    let Some(items) = load(path("FORENSIC_OFFICE_LICENSES", "office_licenses.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| OfficeLicense {
            product: s(&v, &["product", "name"]),
            license_type: s(&v, &["license_type", "type"]),
            status: s(&v, &["status"]),
            expiration: opt_n(&v, &["expiration", "expires"]),
        })
        .filter(|x| !x.product.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct OfficeLicense {
    pub product: String,
    pub license_type: String,
    pub status: String,
    pub expiration: Option<u64>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("office").join(file))
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
fn opt_s(v: &Value, keys: &[&str]) -> Option<String> {
    let x = s(v, keys);
    if x.is_empty() {
        None
    } else {
        Some(x)
    }
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

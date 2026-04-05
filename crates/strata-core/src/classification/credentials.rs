use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct CredentialEntry {
    pub target: String,
    pub username: String,
    pub credential_type: CredentialType,
    pub persist: PersistType,
    pub last_written: u64,
}

#[derive(Debug, Clone, Default)]
pub enum CredentialType {
    #[default]
    Generic,
    DomainPassword,
    DomainCertificate,
    DomainVisiblePassword,
    GenericCertificate,
    DomainExtended,
}

#[derive(Debug, Clone, Default)]
pub enum PersistType {
    #[default]
    Session,
    LocalMachine,
    Enterprise,
}

pub fn get_credential_manager_entries() -> Result<Vec<CredentialEntry>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_CREDENTIAL_MANAGER_ENTRIES",
        "credential_manager_entries.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(parse_credential_entry)
        .filter(|x| !x.target.is_empty() || !x.username.is_empty())
        .collect())
}

pub fn get_windows_credentials() -> Result<Vec<CredentialEntry>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_WINDOWS_CREDENTIALS",
        "windows_credentials.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(parse_credential_entry)
        .filter(|x| !x.target.is_empty() || !x.username.is_empty())
        .collect())
}

pub fn get_web_credentials() -> Result<Vec<WebCredential>, ForensicError> {
    let Some(items) = load(path("FORENSIC_WEB_CREDENTIALS", "web_credentials.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| WebCredential {
            url: s(&v, &["url"]),
            username: s(&v, &["username", "user"]),
            password: s(&v, &["password", "secret"]),
            last_used: opt_n(&v, &["last_used", "last_used_time"]),
        })
        .filter(|x| !x.url.is_empty() || !x.username.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct WebCredential {
    pub url: String,
    pub username: String,
    pub password: String,
    pub last_used: Option<u64>,
}

pub fn get_generic_credentials() -> Result<Vec<CredentialEntry>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_GENERIC_CREDENTIALS",
        "generic_credentials.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(parse_credential_entry)
        .filter(|x| !x.target.is_empty() || !x.username.is_empty())
        .collect())
}

pub fn get_credential_history() -> Result<Vec<CredentialHistoryEntry>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_CREDENTIAL_HISTORY",
        "credential_history.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| CredentialHistoryEntry {
            target: s(&v, &["target"]),
            username: s(&v, &["username", "user"]),
            action: s(&v, &["action"]),
            timestamp: n(&v, &["timestamp", "time"]),
        })
        .filter(|x| !x.target.is_empty() || x.timestamp > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct CredentialHistoryEntry {
    pub target: String,
    pub username: String,
    pub action: String,
    pub timestamp: u64,
}

fn parse_credential_entry(v: Value) -> CredentialEntry {
    CredentialEntry {
        target: s(&v, &["target"]),
        username: s(&v, &["username", "user"]),
        credential_type: credential_type_enum(s(&v, &["credential_type", "type"])),
        persist: persist_type_enum(s(&v, &["persist", "persist_type"])),
        last_written: n(&v, &["last_written", "timestamp"]),
    }
}

fn credential_type_enum(value: String) -> CredentialType {
    match value.to_ascii_lowercase().as_str() {
        "domainpassword" | "domain_password" => CredentialType::DomainPassword,
        "domaincertificate" | "domain_certificate" => CredentialType::DomainCertificate,
        "domainvisiblepassword" | "domain_visible_password" => {
            CredentialType::DomainVisiblePassword
        }
        "genericcertificate" | "generic_certificate" => CredentialType::GenericCertificate,
        "domainextended" | "domain_extended" => CredentialType::DomainExtended,
        _ => CredentialType::Generic,
    }
}

fn persist_type_enum(value: String) -> PersistType {
    match value.to_ascii_lowercase().as_str() {
        "localmachine" | "local_machine" => PersistType::LocalMachine,
        "enterprise" => PersistType::Enterprise,
        _ => PersistType::Session,
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("credentials").join(file))
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

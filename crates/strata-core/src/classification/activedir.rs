use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_ad_users() -> Vec<AdUser> {
    let Some(items) = load(path("FORENSIC_AD_USERS", "ad_users.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AdUser {
            sam_account_name: s(&v, &["sam_account_name", "sam"]),
            display_name: s(&v, &["display_name", "name"]),
            email: s(&v, &["email", "mail"]),
            last_logon: n(&v, &["last_logon"]),
            password_last_set: n(&v, &["password_last_set", "pwd_last_set"]),
            enabled: b(&v, &["enabled"]),
            groups: sa(&v, &["groups", "member_of"]),
        })
        .filter(|x| !x.sam_account_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AdUser {
    pub sam_account_name: String,
    pub display_name: String,
    pub email: String,
    pub last_logon: u64,
    pub password_last_set: u64,
    pub enabled: bool,
    pub groups: Vec<String>,
}

pub fn get_ad_computers() -> Vec<AdComputer> {
    let Some(items) = load(path("FORENSIC_AD_COMPUTERS", "ad_computers.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AdComputer {
            name: s(&v, &["name"]),
            operating_system: s(&v, &["operating_system", "os"]),
            last_logon: n(&v, &["last_logon"]),
            ipv4_address: s(&v, &["ipv4_address", "ip"]),
            member_of: sa(&v, &["member_of", "groups"]),
        })
        .filter(|x| !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AdComputer {
    pub name: String,
    pub operating_system: String,
    pub last_logon: u64,
    pub ipv4_address: String,
    pub member_of: Vec<String>,
}

pub fn get_ad_groups() -> Vec<AdGroup> {
    let Some(items) = load(path("FORENSIC_AD_GROUPS", "ad_groups.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AdGroup {
            name: s(&v, &["name"]),
            description: s(&v, &["description"]),
            members: sa(&v, &["members"]),
            group_scope: s(&v, &["group_scope", "scope"]),
        })
        .filter(|x| !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AdGroup {
    pub name: String,
    pub description: String,
    pub members: Vec<String>,
    pub group_scope: String,
}

pub fn get_ad_ous() -> Vec<AdOu> {
    let Some(items) = load(path("FORENSIC_AD_OUS", "ad_ous.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AdOu {
            name: s(&v, &["name"]),
            distinguished_name: s(&v, &["distinguished_name", "dn"]),
            children: sa(&v, &["children"]),
        })
        .filter(|x| !x.name.is_empty() || !x.distinguished_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AdOu {
    pub name: String,
    pub distinguished_name: String,
    pub children: Vec<String>,
}

pub fn get_ad_gpos() -> Vec<AdGpo> {
    let Some(items) = load(path("FORENSIC_AD_GPOS", "ad_gpos.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| AdGpo {
            name: s(&v, &["name"]),
            gpo_id: s(&v, &["gpo_id", "id"]),
            created: n(&v, &["created"]),
            modified: n(&v, &["modified"]),
            status: s(&v, &["status"]),
        })
        .filter(|x| !x.name.is_empty() || !x.gpo_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AdGpo {
    pub name: String,
    pub gpo_id: String,
    pub created: u64,
    pub modified: u64,
    pub status: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key).map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from("artifacts")
            .join("active_directory")
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

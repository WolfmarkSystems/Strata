use std::env;
use std::path::{Path, PathBuf};

use serde_json::Value;

pub fn get_sam_accounts() -> Vec<SamAccount> {
    get_sam_accounts_from_path(&path("FORENSIC_SAM_ACCOUNTS", "sam_accounts.json"))
}

pub fn get_sam_accounts_from_path(path: &Path) -> Vec<SamAccount> {
    let Some(items) = load(path.to_path_buf()) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SamAccount {
            rid: n(&v, &["rid"]) as u32,
            name: s(
                &v,
                &["name", "username", "account_name", "sam_account_name"],
            ),
            sid: s(&v, &["sid", "object_sid"]),
            account_type: s(&v, &["account_type", "type"]),
            is_disabled: b(&v, &["disabled", "is_disabled"]),
            created_unix: n_opt(&v, &["created_unix", "created_at_unix", "created_at"]),
            last_login_unix: n_opt(&v, &["last_login_unix", "last_logon_unix", "last_logon"]),
        })
        .filter(|x| x.rid > 0 || !x.name.is_empty() || !x.sid.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SamAccount {
    pub rid: u32,
    pub name: String,
    pub sid: String,
    pub account_type: String,
    pub is_disabled: bool,
    pub created_unix: Option<u64>,
    pub last_login_unix: Option<u64>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("accounts").join(file))
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

fn n_opt(v: &Value, keys: &[&str]) -> Option<u64> {
    let value = n(v, keys);
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return x != 0;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            let t = x.trim().to_ascii_lowercase();
            if matches!(t.as_str(), "1" | "true" | "yes" | "disabled") {
                return true;
            }
            if matches!(t.as_str(), "0" | "false" | "no" | "enabled") {
                return false;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_sam_accounts_with_optional_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sam_accounts.json");
        strata_fs::write(
            &file,
            r#"
[
  {
    "rid": 500,
    "sam_account_name": "Administrator",
    "sid": "S-1-5-21-1-2-3-500",
    "account_type": "local",
    "disabled": true,
    "created_unix": 1700000000,
    "last_logon_unix": 1700001234
  },
  {
    "rid": 501,
    "name": "Guest",
    "disabled": "0"
  }
]
"#,
        )
        .unwrap();
        let rows = get_sam_accounts_from_path(&file);

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "Administrator");
        assert!(rows[0].is_disabled);
        assert_eq!(rows[0].created_unix, Some(1_700_000_000));
        assert_eq!(rows[0].last_login_unix, Some(1_700_001_234));
        assert!(!rows[1].is_disabled);
    }
}

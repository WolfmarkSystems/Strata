use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_ldap_users() -> Vec<LdapUser> {
    let path = env::var("FORENSIC_LDAP_USERS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("ldap")
                .join("ldap_users.json")
        });
    let data = match super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(items) = json.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .map(|v| LdapUser {
            dn: v
                .get("dn")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            cn: v
                .get("cn")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
        .filter(|x| !x.dn.is_empty() || !x.cn.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct LdapUser {
    pub dn: String,
    pub cn: String,
}

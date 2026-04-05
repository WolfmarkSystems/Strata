use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_logon_sessions() -> Vec<LogonSession> {
    let Some(items) = load(path("FORENSIC_LOGON_SESSIONS", "logon_sessions.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| LogonSession {
            sid: s(&v, &["sid", "user_sid"]),
            username: s(&v, &["username", "user", "account"]),
        })
        .filter(|x| !x.sid.is_empty() || !x.username.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct LogonSession {
    pub sid: String,
    pub username: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("auth").join(file))
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

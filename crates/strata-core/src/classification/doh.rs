use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_doh_queries() -> Vec<DohQuery> {
    let Some(items) = load(path("FORENSIC_DOH_QUERIES", "doh_queries.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DohQuery {
            timestamp: n(&v, &["timestamp", "time"]),
            query_name: s(&v, &["query_name", "name"]),
            query_type: s(&v, &["query_type", "type"]),
            response: s(&v, &["response", "answer"]),
            doh_server: s(&v, &["doh_server", "server"]),
        })
        .filter(|x| !x.query_name.is_empty() || x.timestamp > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct DohQuery {
    pub timestamp: u64,
    pub query_name: String,
    pub query_type: String,
    pub response: String,
    pub doh_server: String,
}

pub fn get_doh_settings() -> Vec<DohSettings> {
    let Some(items) = load(path("FORENSIC_DOH_SETTINGS", "doh_settings.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DohSettings {
            enabled: b(&v, &["enabled"]),
            doh_servers: sa(&v, &["doh_servers", "servers"]),
            fallback: b(&v, &["fallback", "allow_fallback"]),
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct DohSettings {
    pub enabled: bool,
    pub doh_servers: Vec<String>,
    pub fallback: bool,
}

pub fn get_dns_cache_detailed() -> Vec<DnsCacheDetailed> {
    let Some(items) = load(path(
        "FORENSIC_DNS_CACHE_DETAILED",
        "dns_cache_detailed.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DnsCacheDetailed {
            name: s(&v, &["name", "query_name"]),
            type_: s(&v, &["type_", "type", "record_type"]),
            data: s(&v, &["data", "value"]),
            ttl: n(&v, &["ttl"]) as u32,
            timestamp: n(&v, &["timestamp", "time"]),
        })
        .filter(|x| !x.name.is_empty() || !x.data.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct DnsCacheDetailed {
    pub name: String,
    pub type_: String,
    pub data: String,
    pub ttl: u32,
    pub timestamp: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("network").join(file))
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
        if let Some(items) = v.get(*k).and_then(Value::as_array) {
            return items
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
        }
    }
    Vec::new()
}

use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_malware_yara() -> Vec<YaraRule> {
    let Some(items) = load(path("FORENSIC_YARA_RESULTS", "yara_results.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| YaraRule {
            name: s(&v, &["name", "rule"]),
            matches: matches(&v),
        })
        .filter(|x| !x.name.is_empty() || !x.matches.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct YaraRule {
    pub name: String,
    pub matches: Vec<YaraMatch>,
}

#[derive(Debug, Clone, Default)]
pub struct YaraMatch {
    pub rule: String,
    pub offset: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("yara").join(file))
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

fn matches(v: &Value) -> Vec<YaraMatch> {
    let Some(items) = v.get("matches").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|x| YaraMatch {
            rule: s(x, &["rule", "name"]),
            offset: n(x, &["offset"]),
        })
        .filter(|x| !x.rule.is_empty() || x.offset > 0)
        .collect()
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

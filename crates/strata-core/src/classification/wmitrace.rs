use std::env;
use std::path::{Path, PathBuf};

use serde_json::Value;

pub fn get_wmi_traces() -> Vec<WmiTrace> {
    get_wmi_traces_from_path(&path("FORENSIC_WMI_TRACES", "traces.json"))
}

pub fn get_wmi_traces_from_path(path: &Path) -> Vec<WmiTrace> {
    let Some(items) = load(path.to_path_buf()) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WmiTrace {
            timestamp: n(&v, &["timestamp", "time_utc", "occurred_utc"]),
            namespace: s(&v, &["namespace", "wmi_namespace"]),
        })
        .filter(|x| x.timestamp > 0 || !x.namespace.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WmiTrace {
    pub timestamp: u64,
    pub namespace: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("wmi").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let parsed = serde_json::from_slice::<Value>(&data)
        .ok()
        .and_then(|v| match v {
            Value::Array(items) => Some(items),
            Value::Object(map) => map
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .or_else(|| map.get("records").and_then(Value::as_array).cloned())
                .or_else(|| map.get("events").and_then(Value::as_array).cloned()),
            _ => None,
        });
    if parsed.is_some() {
        return parsed;
    }

    // Lightweight fallback for line-based exports: "<timestamp>,<namespace>"
    let content = String::from_utf8_lossy(&data);
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some((ts, ns)) = trimmed.split_once(',') {
            out.push(serde_json::json!({
                "timestamp": ts.trim(),
                "namespace": ns.trim(),
            }));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_wmi_traces_from_records_object() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("traces.json");
        strata_fs::write(
            &file,
            r#"{"records":[{"timestamp":"1700001111","namespace":"root\\subscription"}]}"#,
        )
        .unwrap();

        let rows = get_wmi_traces_from_path(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timestamp, 1_700_001_111);
    }

    #[test]
    fn parse_wmi_traces_line_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("traces.txt");
        strata_fs::write(&file, "1700002000,root\\cimv2\n").unwrap();

        let rows = get_wmi_traces_from_path(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].namespace, "root\\cimv2");
    }
}

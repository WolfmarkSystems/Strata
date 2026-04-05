use std::env;
use std::path::{Path, PathBuf};

use serde_json::Value;

pub fn get_wmi_persistence() -> Vec<WmiPersist> {
    let path = env::var("FORENSIC_WMI_PERSIST")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("wmi")
                .join("persistence.json")
        });
    get_wmi_persistence_from_path(&path)
}

pub fn get_wmi_persistence_from_path(path: &Path) -> Vec<WmiPersist> {
    let data = match super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    parse_wmi_persistence_payload(&data)
}

fn parse_wmi_persistence_payload(data: &[u8]) -> Vec<WmiPersist> {
    let items = match serde_json::from_slice::<Value>(data) {
        Ok(v) => match v {
            Value::Array(items) => items,
            Value::Object(map) => map
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .or_else(|| map.get("records").and_then(Value::as_array).cloned())
                .or_else(|| map.get("bindings").and_then(Value::as_array).cloned())
                .unwrap_or_else(|| vec![Value::Object(map)]),
            _ => Vec::new(),
        },
        Err(_) => parse_line_fallback(String::from_utf8_lossy(data).as_ref()),
    };

    items
        .iter()
        .map(|item| WmiPersist {
            consumer: item
                .get("consumer")
                .or_else(|| item.get("consumer_name"))
                .or_else(|| item.get("command_line_template"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            filter: item
                .get("filter")
                .or_else(|| item.get("query"))
                .or_else(|| item.get("event_filter"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
        .filter(|x| !x.consumer.is_empty() || !x.filter.is_empty())
        .collect()
}

fn parse_line_fallback(content: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some((consumer, filter)) = trimmed.split_once(',') {
            out.push(serde_json::json!({
                "consumer": consumer.trim(),
                "filter": filter.trim()
            }));
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim().eq_ignore_ascii_case("consumer") {
                out.push(serde_json::json!({ "consumer": v.trim() }));
            } else if k.trim().eq_ignore_ascii_case("filter") {
                out.push(serde_json::json!({ "filter": v.trim() }));
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct WmiPersist {
    pub consumer: String,
    pub filter: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_wmi_persistence_from_object_records() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("persist.json");
        strata_fs::write(
            &file,
            r#"{"records":[{"consumer":"cmd /c calc.exe","filter":"SELECT * FROM XEvent"}]}"#,
        )
        .unwrap();

        let rows = get_wmi_persistence_from_path(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].consumer, "cmd /c calc.exe");
    }

    #[test]
    fn parse_wmi_persistence_line_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("persist.txt");
        strata_fs::write(
            &file,
            "consumer=cmd.exe /c beacon.ps1\nfilter=SELECT * FROM __InstanceCreationEvent\n",
        )
        .unwrap();

        let rows = get_wmi_persistence_from_path(&file);
        assert!(!rows.is_empty());
    }
}

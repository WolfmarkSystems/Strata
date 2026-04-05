use std::env;
use std::path::{Path, PathBuf};

use serde_json::Value;

pub fn get_wmi_class_instances() -> Vec<WmiInstance> {
    let path = env::var("FORENSIC_WMI_INSTANCES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("wmi")
                .join("instances.json")
        });
    get_wmi_class_instances_from_path(&path)
}

pub fn get_wmi_class_instances_from_path(path: &Path) -> Vec<WmiInstance> {
    let data = match super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let items = match serde_json::from_slice::<Value>(&data) {
        Ok(v) => match v {
            Value::Array(items) => items,
            Value::Object(map) => map
                .get("instances")
                .and_then(Value::as_array)
                .cloned()
                .or_else(|| map.get("items").and_then(Value::as_array).cloned())
                .or_else(|| map.get("records").and_then(Value::as_array).cloned())
                .unwrap_or_else(|| vec![Value::Object(map)]),
            _ => Vec::new(),
        },
        Err(_) => parse_line_fallback(String::from_utf8_lossy(&data).as_ref()),
    };
    items
        .iter()
        .map(|item| WmiInstance {
            class: item
                .get("class")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            properties: item
                .get("properties")
                .and_then(Value::as_object)
                .map(|obj| {
                    obj.iter()
                        .map(|(k, v)| {
                            let value = if let Some(s) = v.as_str() {
                                s.to_string()
                            } else {
                                v.to_string()
                            };
                            (k.clone(), value)
                        })
                        .collect::<Vec<(String, String)>>()
                })
                .unwrap_or_default(),
        })
        .filter(|x| !x.class.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WmiInstance {
    pub class: String,
    pub properties: Vec<(String, String)>,
}

fn parse_line_fallback(content: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        // Expected fallback form: "ClassName,key=value"
        if let Some((class, kv)) = trimmed.split_once(',') {
            let mut obj = serde_json::Map::new();
            obj.insert("class".to_string(), Value::String(class.trim().to_string()));
            if let Some((k, v)) = kv.split_once('=') {
                obj.insert(
                    "properties".to_string(),
                    serde_json::json!({ k.trim(): v.trim() }),
                );
            }
            out.push(Value::Object(obj));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_wmi_instances_from_object_records() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("instances.json");
        strata_fs::write(
            &file,
            r#"{"instances":[{"class":"Win32_Process","properties":{"Name":"cmd.exe"}}]}"#,
        )
        .unwrap();

        let rows = get_wmi_class_instances_from_path(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].class, "Win32_Process");
    }

    #[test]
    fn parse_wmi_instances_line_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("instances.txt");
        strata_fs::write(&file, "Win32_Process,Name=cmd.exe\n").unwrap();

        let rows = get_wmi_class_instances_from_path(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].class, "Win32_Process");
    }
}

use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_installed_fonts() -> Vec<String> {
    let path = path("FORENSIC_SYSTEM_FONTS", "installed_fonts.json");
    let data = match super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    if let Some(items) = json.as_array() {
        return items
            .iter()
            .filter_map(|x| x.as_str().map(ToString::to_string))
            .collect();
    }
    Vec::new()
}

pub fn get_system_timezone() -> String {
    let path = path("FORENSIC_SYSTEM_TIMEZONE", "system_timezone.json");
    let data = match super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    let json: Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    json.get("timezone")
        .and_then(Value::as_str)
        .or_else(|| json.get("tz").and_then(Value::as_str))
        .unwrap_or_default()
        .to_string()
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("system").join(file))
}

use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct AccessibilitySettings {
    pub narrator_enabled: bool,
    pub magnifier_enabled: bool,
    pub high_contrast_enabled: bool,
    pub keyboard_filter_enabled: bool,
    pub sticky_keys_enabled: bool,
    pub toggle_keys_enabled: bool,
    pub filter_keys_enabled: bool,
}

pub fn get_accessibility_settings() -> Result<AccessibilitySettings, ForensicError> {
    Ok(AccessibilitySettings {
        narrator_enabled: false,
        magnifier_enabled: false,
        high_contrast_enabled: false,
        keyboard_filter_enabled: false,
        sticky_keys_enabled: false,
        toggle_keys_enabled: false,
        filter_keys_enabled: false,
    })
}

pub fn get_narrator_history() -> Result<Vec<NarratorProfile>, ForensicError> {
    let Some(items) = load(path("FORENSIC_NARRATOR_HISTORY", "narrator_history.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| NarratorProfile {
            voice: s(&v, &["voice"]),
            rate: n(&v, &["rate"]) as u32,
            volume: n(&v, &["volume"]) as u32,
            pitch: n(&v, &["pitch"]) as u32,
        })
        .filter(|x| !x.voice.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct NarratorProfile {
    pub voice: String,
    pub rate: u32,
    pub volume: u32,
    pub pitch: u32,
}

pub fn get_magnifier_settings() -> Result<MagnifierSettings, ForensicError> {
    Ok(MagnifierSettings {
        enabled: false,
        mode: "fullscreen".to_string(),
        magnification_level: 200,
    })
}

#[derive(Debug, Clone, Default)]
pub struct MagnifierSettings {
    pub enabled: bool,
    pub mode: String,
    pub magnification_level: u32,
}

pub fn get_high_contrast_settings() -> Result<HighContrastSettings, ForensicError> {
    Ok(HighContrastSettings {
        enabled: false,
        scheme: "".to_string(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct HighContrastSettings {
    pub enabled: bool,
    pub scheme: String,
}

pub fn get_ease_of_access_log() -> Result<Vec<EaseOfAccessLogEntry>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_EASE_OF_ACCESS_LOG",
        "ease_of_access_log.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| EaseOfAccessLogEntry {
            timestamp: n(&v, &["timestamp", "time"]),
            setting_name: s(&v, &["setting_name", "setting"]),
            old_value: s(&v, &["old_value", "old"]),
            new_value: s(&v, &["new_value", "new"]),
        })
        .filter(|x| x.timestamp > 0 || !x.setting_name.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct EaseOfAccessLogEntry {
    pub timestamp: u64,
    pub setting_name: String,
    pub old_value: String,
    pub new_value: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("accessibility").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let v: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = v.as_array() {
        Some(items.clone())
    } else if v.is_object() {
        v.get("items")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| v.get("results").and_then(Value::as_array).cloned())
            .or_else(|| Some(vec![v]))
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
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return x as u64;
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return n;
            }
        }
    }
    0
}

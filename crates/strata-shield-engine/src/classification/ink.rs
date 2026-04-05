use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct InkStroke {
    pub id: String,
    pub stroke_data: Vec<u8>,
    pub created_time: u64,
    pub color: String,
    pub thickness: f32,
}

pub fn get_ink_workspace() -> Result<InkWorkspace, ForensicError> {
    Ok(InkWorkspace {
        strokes: vec![],
        last_modified: None,
    })
}

#[derive(Debug, Clone, Default)]
pub struct InkWorkspace {
    pub strokes: Vec<InkStroke>,
    pub last_modified: Option<u64>,
}

pub fn get_ink_recognizer_info() -> Result<Vec<InkRecognizer>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_INK_RECOGNIZER_INFO",
        "ink_recognizer_info.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| InkRecognizer {
            name: s(&v, &["name"]),
            language: s(&v, &["language", "lang"]),
            capabilities: s(&v, &["capabilities"]),
        })
        .filter(|x| !x.name.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct InkRecognizer {
    pub name: String,
    pub language: String,
    pub capabilities: String,
}

pub fn get_pen_settings() -> Result<PenSettings, ForensicError> {
    Ok(PenSettings {
        pen_button_action: "right_click".to_string(),
        erase_action: "stroke".to_string(),
        pressure_sensitivity: true,
    })
}

#[derive(Debug, Clone, Default)]
pub struct PenSettings {
    pub pen_button_action: String,
    pub erase_action: String,
    pub pressure_sensitivity: bool,
}

pub fn get_whiteboard_sessions() -> Result<Vec<WhiteboardSession>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_WHITEBOARD_SESSIONS",
        "whiteboard_sessions.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| WhiteboardSession {
            id: s(&v, &["id", "session_id"]),
            created: n(&v, &["created", "created_time"]),
            modified: n(&v, &["modified", "modified_time"]),
            stroke_count: n(&v, &["stroke_count", "count"]) as u32,
        })
        .filter(|x| !x.id.is_empty() || x.created > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct WhiteboardSession {
    pub id: String,
    pub created: u64,
    pub modified: u64,
    pub stroke_count: u32,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("ink").join(file))
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

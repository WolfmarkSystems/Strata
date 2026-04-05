use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct SnippingToolCapture {
    pub id: String,
    pub capture_time: u64,
    pub file_path: String,
    pub capture_type: CaptureType,
    pub dimensions: (u32, u32),
}

#[derive(Debug, Clone, Default)]
pub enum CaptureType {
    #[default]
    FullScreen,
    Window,
    Rectangular,
    Freeform,
}

pub fn get_snipping_tool_history() -> Result<Vec<SnippingToolCapture>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_SNIPPING_HISTORY",
        "snipping_tool_history.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| SnippingToolCapture {
            id: s(&v, &["id", "capture_id"]),
            capture_time: n(&v, &["capture_time", "timestamp"]),
            file_path: s(&v, &["file_path", "path"]),
            capture_type: capture_type_enum(s(&v, &["capture_type", "type"])),
            dimensions: (n(&v, &["width"]) as u32, n(&v, &["height"]) as u32),
        })
        .filter(|x| !x.id.is_empty() || x.capture_time > 0 || !x.file_path.is_empty())
        .collect())
}

pub fn get_snipping_tool_settings() -> Result<SnipSettings, ForensicError> {
    Ok(SnipSettings {
        default_format: "png".to_string(),
        auto_copy: true,
        include_cursor: false,
    })
}

#[derive(Debug, Clone, Default)]
pub struct SnipSettings {
    pub default_format: String,
    pub auto_copy: bool,
    pub include_cursor: bool,
}

pub fn get_clipboard_history() -> Result<Vec<ClipboardEntry>, ForensicError> {
    let Some(items) = load(path("FORENSIC_CLIPBOARD_HISTORY", "clipboard_history.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| ClipboardEntry {
            timestamp: n(&v, &["timestamp", "time"]),
            content_type: s(&v, &["content_type", "type"]),
            content: s(&v, &["content", "value"]),
            source_app: s_opt(&v, &["source_app", "app"]),
        })
        .filter(|x| x.timestamp > 0 || !x.content.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct ClipboardEntry {
    pub timestamp: u64,
    pub content_type: String,
    pub content: String,
    pub source_app: Option<String>,
}

pub fn get_clipboard_file_drop() -> Result<Vec<ClipboardFile>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_CLIPBOARD_FILE_DROP",
        "clipboard_file_drop.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| ClipboardFile {
            file_path: s(&v, &["file_path", "path"]),
            file_size: n(&v, &["file_size", "size"]),
            copy_time: n(&v, &["copy_time", "timestamp"]),
        })
        .filter(|x| !x.file_path.is_empty() || x.copy_time > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct ClipboardFile {
    pub file_path: String,
    pub file_size: u64,
    pub copy_time: u64,
}

fn capture_type_enum(value: String) -> CaptureType {
    match value.to_ascii_lowercase().as_str() {
        "window" => CaptureType::Window,
        "rectangular" => CaptureType::Rectangular,
        "freeform" => CaptureType::Freeform,
        _ => CaptureType::FullScreen,
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("snipping").join(file))
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

fn s_opt(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return Some(x.to_string());
        }
    }
    None
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

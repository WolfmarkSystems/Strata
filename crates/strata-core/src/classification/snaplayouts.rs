use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_snap_layouts() -> Vec<SnapLayout> {
    let Some(items) = load(path("FORENSIC_SNAP_LAYOUTS", "snap_layouts.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SnapLayout {
            layout_id: s(&v, &["layout_id", "id"]),
            windows: windows(&v),
            timestamp: n(&v, &["timestamp", "time"]),
        })
        .filter(|x| !x.layout_id.is_empty() || !x.windows.is_empty() || x.timestamp > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SnapLayout {
    pub layout_id: String,
    pub windows: Vec<SnapWindow>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SnapWindow {
    pub window_title: String,
    pub process_name: String,
    pub position: SnapPosition,
}

#[derive(Debug, Clone, Default)]
pub struct SnapPosition {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

pub fn get_snap_history() -> Vec<SnapHistory> {
    let Some(items) = load(path("FORENSIC_SNAP_HISTORY", "snap_history.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SnapHistory {
            timestamp: n(&v, &["timestamp", "time"]),
            layouts: history_layouts(&v),
        })
        .filter(|x| x.timestamp > 0 || !x.layouts.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SnapHistory {
    pub timestamp: u64,
    pub layouts: Vec<SnapLayout>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("ui").join(file))
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

fn windows(v: &Value) -> Vec<SnapWindow> {
    let Some(items) = v.get("windows").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|x| SnapWindow {
            window_title: s(x, &["window_title", "title"]),
            process_name: s(x, &["process_name", "process"]),
            position: SnapPosition {
                x: n(x, &["x"]) as u32,
                y: n(x, &["y"]) as u32,
                width: n(x, &["width", "w"]) as u32,
                height: n(x, &["height", "h"]) as u32,
            },
        })
        .filter(|x| !x.window_title.is_empty() || !x.process_name.is_empty())
        .collect()
}

fn history_layouts(v: &Value) -> Vec<SnapLayout> {
    let Some(items) = v.get("layouts").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|x| SnapLayout {
            layout_id: s(x, &["layout_id", "id"]),
            windows: windows(x),
            timestamp: n(x, &["timestamp", "time"]),
        })
        .filter(|x| !x.layout_id.is_empty() || !x.windows.is_empty() || x.timestamp > 0)
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

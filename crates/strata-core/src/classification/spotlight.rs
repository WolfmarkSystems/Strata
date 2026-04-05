use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct SpotlightImage {
    pub id: String,
    pub image_path: String,
    pub thumbnail_path: String,
    pub title: String,
    pub description: String,
    pub action_url: Option<String>,
    pub start_time: u64,
    pub end_time: Option<u64>,
}

pub fn get_spotlight_history() -> Result<Vec<SpotlightImage>, ForensicError> {
    let path = env::var("FORENSIC_SPOTLIGHT_HISTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("spotlight")
                .join("spotlight_history.json")
        });
    let Ok(data) = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
    else {
        return Ok(Vec::new());
    };
    let Ok(v) = serde_json::from_slice::<Value>(&data) else {
        return Ok(Vec::new());
    };
    let items = v.as_array().cloned().unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| SpotlightImage {
            id: s(&x, &["id"]),
            image_path: s(&x, &["image_path", "path"]),
            thumbnail_path: s(&x, &["thumbnail_path"]),
            title: s(&x, &["title"]),
            description: s(&x, &["description"]),
            action_url: s_opt(&x, &["action_url", "url"]),
            start_time: n(&x, &["start_time", "timestamp"]),
            end_time: opt_n(&x, &["end_time"]),
        })
        .filter(|x| !x.id.is_empty() || !x.image_path.is_empty() || x.start_time > 0)
        .collect())
}

pub fn get_spotlight_settings() -> Result<SpotlightSettings, ForensicError> {
    Ok(SpotlightSettings {
        enabled: true,
        lock_screen: true,
        desktop: true,
    })
}

#[derive(Debug, Clone, Default)]
pub struct SpotlightSettings {
    pub enabled: bool,
    pub lock_screen: bool,
    pub desktop: bool,
}

pub fn get_spotlight_cache_path() -> String {
    r"C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager\LocalState\Assets".to_string()
}

pub fn get_spotlight_feedback() -> Result<SpotlightFeedback, ForensicError> {
    let path = env::var("FORENSIC_SPOTLIGHT_FEEDBACK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("spotlight")
                .join("spotlight_feedback.json")
        });
    let Ok(data) = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
    else {
        return Ok(SpotlightFeedback {
            likes: Vec::new(),
            dislikes: Vec::new(),
        });
    };
    let Ok(v) = serde_json::from_slice::<Value>(&data) else {
        return Ok(SpotlightFeedback {
            likes: Vec::new(),
            dislikes: Vec::new(),
        });
    };
    Ok(SpotlightFeedback {
        likes: str_vec(&v, &["likes"]),
        dislikes: str_vec(&v, &["dislikes"]),
    })
}

#[derive(Debug, Clone, Default)]
pub struct SpotlightFeedback {
    pub likes: Vec<String>,
    pub dislikes: Vec<String>,
}

pub fn get_daily_spotlight() -> Result<SpotlightImage, ForensicError> {
    let mut items = get_spotlight_history()?;
    items.sort_by_key(|x| x.start_time);
    Ok(items.pop().unwrap_or_default())
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
    opt_n(v, keys).unwrap_or(0)
}

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return Some(x as u64);
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

fn str_vec(v: &Value, keys: &[&str]) -> Vec<String> {
    for k in keys {
        if let Some(items) = v.get(*k).and_then(Value::as_array) {
            return items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect();
        }
    }
    Vec::new()
}

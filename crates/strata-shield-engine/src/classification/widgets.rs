use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_widget_board() -> Vec<WidgetInfo> {
    let Some(items) = load(path("FORENSIC_WIDGET_BOARD", "widget_board.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WidgetInfo {
            widget_id: s(&v, &["widget_id", "id"]),
            widget_name: s(&v, &["widget_name", "name"]),
            provider: s(&v, &["provider"]),
            last_updated: n(&v, &["last_updated", "updated"]),
        })
        .filter(|x| !x.widget_id.is_empty() || !x.widget_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WidgetInfo {
    pub widget_id: String,
    pub widget_name: String,
    pub provider: String,
    pub last_updated: u64,
}

pub fn get_widget_feeds() -> Vec<WidgetFeed> {
    let Some(items) = load(path("FORENSIC_WIDGET_FEEDS", "widget_feeds.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WidgetFeed {
            feed_id: s(&v, &["feed_id", "id"]),
            title: s(&v, &["title", "name"]),
            items: feed_items(&v),
        })
        .filter(|x| !x.feed_id.is_empty() || !x.title.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WidgetFeed {
    pub feed_id: String,
    pub title: String,
    pub items: Vec<WidgetFeedItem>,
}

#[derive(Debug, Clone, Default)]
pub struct WidgetFeedItem {
    pub title: String,
    pub subtitle: String,
    pub timestamp: u64,
    pub url: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("widgets").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
}

fn feed_items(v: &Value) -> Vec<WidgetFeedItem> {
    let Some(items) = v.get("items").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|x| WidgetFeedItem {
            title: s(x, &["title"]),
            subtitle: s(x, &["subtitle", "summary"]),
            timestamp: n(x, &["timestamp", "published"]),
            url: s(x, &["url", "link"]),
        })
        .filter(|x| !x.title.is_empty() || !x.url.is_empty())
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

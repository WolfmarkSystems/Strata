use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_search_index_content() -> Vec<SearchIndexEntry> {
    let Some(items) = load(path(
        "FORENSIC_SEARCH_INDEX_CONTENT",
        "search_index_content.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SearchIndexEntry {
            document_id: n(&v, &["document_id", "id"]),
            file_path: s(&v, &["file_path", "path"]),
            title: s(&v, &["title"]),
            content_snippet: s(&v, &["content_snippet", "snippet"]),
            indexed: n(&v, &["indexed", "indexed_at"]),
            modified: n(&v, &["modified", "modified_at"]),
        })
        .filter(|x| x.document_id != 0 || !x.file_path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SearchIndexEntry {
    pub document_id: u64,
    pub file_path: String,
    pub title: String,
    pub content_snippet: String,
    pub indexed: u64,
    pub modified: u64,
}

pub fn get_search_history() -> Vec<SearchQuery> {
    let Some(items) = load(path("FORENSIC_SEARCH_HISTORY", "search_history.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SearchQuery {
            query: s(&v, &["query"]),
            timestamp: n(&v, &["timestamp"]),
            result_count: n(&v, &["result_count", "count"]) as u32,
        })
        .filter(|x| !x.query.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub query: String,
    pub timestamp: u64,
    pub result_count: u32,
}

pub fn get_cortana_history() -> Vec<CortanaEntry> {
    let Some(items) = load(path("FORENSIC_CORTANA_HISTORY", "cortana_history.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| CortanaEntry {
            query: s(&v, &["query"]),
            response: s(&v, &["response"]),
            timestamp: n(&v, &["timestamp"]),
            app_launched: opt_s(&v, &["app_launched", "app"]),
        })
        .filter(|x| !x.query.is_empty() || !x.response.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct CortanaEntry {
    pub query: String,
    pub response: String,
    pub timestamp: u64,
    pub app_launched: Option<String>,
}

pub fn get_indexed_locations() -> Vec<IndexedLocation> {
    let Some(items) = load(path(
        "FORENSIC_SEARCH_INDEXED_LOCATIONS",
        "indexed_locations.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| IndexedLocation {
            path: s(&v, &["path"]),
            included: b(&v, &["included"]),
            item_count: n(&v, &["item_count", "count"]),
        })
        .filter(|x| !x.path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct IndexedLocation {
    pub path: String,
    pub included: bool,
    pub item_count: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("search").join(file))
}
fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
}
fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}
fn opt_s(v: &Value, keys: &[&str]) -> Option<String> {
    let x = s(v, keys);
    if x.is_empty() {
        None
    } else {
        Some(x)
    }
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
fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}

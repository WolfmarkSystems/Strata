use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct WindowsSearchIndex {
    pub index_path: String,
    pub indexed_locations: Vec<IndexedLocation>,
    pub last_update: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct IndexedLocation {
    pub path: String,
    pub file_count: u64,
    pub size_bytes: u64,
    pub last_indexed: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct SearchHistoryEntry {
    pub query: String,
    pub timestamp: u64,
    pub result_count: u32,
    pub user: String,
}

#[derive(Debug, Clone, Default)]
pub struct SearchResultEntry {
    pub file_path: String,
    pub file_name: String,
    pub file_extension: String,
    pub file_size: u64,
    pub modified_time: Option<u64>,
    pub created_time: Option<u64>,
    pub accessed_time: Option<u64>,
    pub rank_score: f32,
    pub search_properties: HashMap<String, String>,
}

pub fn get_windows_search_paths() -> Vec<String> {
    vec![
        r"C:\ProgramData\Microsoft\Search".to_string(),
        r"C:\Program Files\Windows Search".to_string(),
    ]
}

pub fn parse_search_index(base_path: &Path) -> Result<WindowsSearchIndex, ForensicError> {
    let overview_path = env::var("FORENSIC_SEARCH_INDEX_OVERVIEW")
        .map(PathBuf::from)
        .unwrap_or_else(|_| base_path.join("index_overview.json"));
    let mut index = WindowsSearchIndex {
        index_path: base_path.to_string_lossy().to_string(),
        // Safe: fills optional preset fields with known defaults
        ..Default::default()
    };
    if let Some(items) = load(overview_path) {
        index.indexed_locations = items
            .into_iter()
            .map(|v| IndexedLocation {
                path: s(&v, &["path", "location"]),
                file_count: n(&v, &["file_count", "count"]),
                size_bytes: n(&v, &["size_bytes", "size"]),
                last_indexed: opt_n(&v, &["last_indexed", "timestamp"]),
            })
            .filter(|x| !x.path.is_empty())
            .collect();
        index.last_update = index
            .indexed_locations
            .iter()
            .filter_map(|x| x.last_indexed)
            .max();
    }
    Ok(index)
}

pub fn scan_search_history(user_path: &Path) -> Result<Vec<SearchHistoryEntry>, ForensicError> {
    let history_path = env::var("FORENSIC_SEARCH_HISTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| user_path.join("search_history.json"));
    let Some(items) = load(history_path) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| SearchHistoryEntry {
            query: s(&v, &["query"]),
            timestamp: n(&v, &["timestamp", "time"]),
            result_count: n(&v, &["result_count", "count"]) as u32,
            user: s(&v, &["user"]),
        })
        .filter(|x| !x.query.is_empty() || x.timestamp > 0)
        .collect())
}

pub fn search_indexed_files(
    index_path: &Path,
    query: &str,
) -> Result<Vec<SearchResultEntry>, ForensicError> {
    let history_file = index_path.join("indexed_files.json");
    let path = env::var("FORENSIC_SEARCH_INDEXED_FILES")
        .map(PathBuf::from)
        .unwrap_or(history_file);
    let Some(items) = load(path) else {
        return Ok(Vec::new());
    };
    let q = query.to_ascii_lowercase();
    Ok(items
        .into_iter()
        .map(|v| SearchResultEntry {
            file_path: s(&v, &["file_path", "path"]),
            file_name: s(&v, &["file_name", "name"]),
            file_extension: s(&v, &["file_extension", "extension"]),
            file_size: n(&v, &["file_size", "size"]),
            modified_time: opt_n(&v, &["modified_time"]),
            created_time: opt_n(&v, &["created_time"]),
            accessed_time: opt_n(&v, &["accessed_time"]),
            rank_score: f(&v, &["rank_score", "score"]),
            search_properties: map_str(&v, &["search_properties", "properties"]),
        })
        .filter(|x| {
            q.is_empty()
                || x.file_name.to_ascii_lowercase().contains(&q)
                || x.file_path.to_ascii_lowercase().contains(&q)
        })
        .collect())
}

pub fn get_recent_searches() -> Result<Vec<SearchHistoryEntry>, ForensicError> {
    let Some(items) = load(path("FORENSIC_RECENT_SEARCHES", "recent_searches.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| SearchHistoryEntry {
            query: s(&v, &["query"]),
            timestamp: n(&v, &["timestamp", "time"]),
            result_count: n(&v, &["result_count", "count"]) as u32,
            user: s(&v, &["user"]),
        })
        .filter(|x| !x.query.is_empty() || x.timestamp > 0)
        .collect())
}

pub fn get_indexed_extensions() -> Vec<String> {
    vec![
        ".txt".to_string(),
        ".doc".to_string(),
        ".docx".to_string(),
        ".pdf".to_string(),
        ".xls".to_string(),
        ".xlsx".to_string(),
        ".ppt".to_string(),
        ".pptx".to_string(),
        ".jpg".to_string(),
        ".png".to_string(),
        ".mp3".to_string(),
        ".mp4".to_string(),
        ".zip".to_string(),
        ".rar".to_string(),
    ]
}

pub fn get_index_statistics(index_path: &Path) -> Result<HashMap<String, u64>, ForensicError> {
    let mut stats = HashMap::new();
    let rows = search_indexed_files(index_path, "")?;
    let total_files = rows.len() as u64;
    let total_size = rows.iter().map(|x| x.file_size).sum::<u64>();
    let index_size = strata_fs::metadata(index_path.join("indexed_files.json"))
        .map(|m| m.len())
        .unwrap_or(0);
    stats.insert("total_files".to_string(), total_files);
    stats.insert("total_size".to_string(), total_size);
    stats.insert("index_size".to_string(), index_size);
    Ok(stats)
}

pub fn scan_search_index_directory(base_path: &Path) -> Result<WindowsSearchIndex, ForensicError> {
    parse_search_index(base_path)
}

pub fn extract_searchable_properties() -> Vec<String> {
    vec![
        "System.FileName".to_string(),
        "System.DateModified".to_string(),
        "System.DateCreated".to_string(),
        "System.DateAccessed".to_string(),
        "System.Size".to_string(),
        "System.Kind".to_string(),
        "System.Author".to_string(),
        "System.Title".to_string(),
        "System.Subject".to_string(),
        "System.Keywords".to_string(),
        "System.Comment".to_string(),
        "System.ApplicationName".to_string(),
    ]
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("search").join(file))
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

fn f(v: &Value, keys: &[&str]) -> f32 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_f64) {
            return x as f32;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<f32>() {
                return n;
            }
        }
    }
    0.0
}

fn map_str(v: &Value, keys: &[&str]) -> HashMap<String, String> {
    for k in keys {
        if let Some(obj) = v.get(*k).and_then(Value::as_object) {
            return obj
                .iter()
                .map(|(k, x)| {
                    let value = x
                        .as_str()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| x.to_string());
                    (k.clone(), value)
                })
                .collect();
        }
    }
    HashMap::new()
}

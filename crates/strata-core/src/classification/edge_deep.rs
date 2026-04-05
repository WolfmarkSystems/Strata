use std::env;
use std::path::PathBuf;

use rusqlite::Connection;

pub fn get_edge_history() -> Vec<EdgeHistory> {
    let mut out = Vec::new();
    for db_path in edge_history_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT url, title, last_visit_time, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 2000",
        ) else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            let raw_time: i64 = row.get(2).unwrap_or(0);
            Ok(EdgeHistory {
                url: row.get::<_, String>(0).unwrap_or_default(),
                title: row.get::<_, String>(1).unwrap_or_default(),
                visit_time: chrome_time_to_unix(raw_time).unwrap_or(0),
                visit_count: row.get::<_, i64>(3).unwrap_or(0).max(0) as u32,
                browser_state: "history".to_string(),
            })
        });
        if let Ok(iter) = rows {
            for item in iter.flatten() {
                out.push(item);
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct EdgeHistory {
    pub url: String,
    pub title: String,
    pub visit_time: u64,
    pub visit_count: u32,
    pub browser_state: String,
}

pub fn get_edge_downloads() -> Vec<EdgeDownload> {
    let mut out = Vec::new();
    for db_path in edge_history_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let query = r#"
SELECT
  COALESCE(u.url, ''),
  COALESCE(d.target_path, ''),
  COALESCE(d.start_time, 0),
  COALESCE(d.total_bytes, 0),
  COALESCE(d.state, 0)
FROM downloads d
LEFT JOIN urls u ON u.id = d.tab_url
ORDER BY d.start_time DESC
LIMIT 2000
"#;
        let Ok(mut stmt) = conn.prepare(query) else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            let state_num: i64 = row.get(4).unwrap_or(0);
            Ok(EdgeDownload {
                url: row.get::<_, String>(0).unwrap_or_default(),
                file_path: row.get::<_, String>(1).unwrap_or_default(),
                start_time: chrome_time_to_unix(row.get::<_, i64>(2).unwrap_or(0)).unwrap_or(0),
                size: row.get::<_, i64>(3).unwrap_or(0).max(0) as u64,
                state: map_download_state(state_num),
            })
        });
        if let Ok(iter) = rows {
            for item in iter.flatten() {
                out.push(item);
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct EdgeDownload {
    pub url: String,
    pub file_path: String,
    pub start_time: u64,
    pub size: u64,
    pub state: String,
}

pub fn get_edge_passwords() -> Vec<EdgePassword> {
    vec![]
}

#[derive(Debug, Clone, Default)]
pub struct EdgePassword {
    pub origin_url: String,
    pub username: String,
    pub password: String,
    pub date_created: u64,
}

pub fn get_edge_cookies() -> Vec<EdgeCookie> {
    let mut out = Vec::new();
    for db_path in edge_cookie_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT host_key, name, path, expires_utc FROM cookies ORDER BY expires_utc DESC LIMIT 5000",
        ) else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            let raw_exp: i64 = row.get(3).unwrap_or(0);
            Ok(EdgeCookie {
                host: row.get::<_, String>(0).unwrap_or_default(),
                name: row.get::<_, String>(1).unwrap_or_default(),
                value: "".to_string(),
                path: row.get::<_, String>(2).unwrap_or_default(),
                expiration: chrome_time_to_unix(raw_exp),
            })
        });
        if let Ok(iter) = rows {
            for item in iter.flatten() {
                out.push(item);
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct EdgeCookie {
    pub host: String,
    pub name: String,
    pub value: String,
    pub path: String,
    pub expiration: Option<u64>,
}

pub fn get_edge_tabs() -> Vec<EdgeTab> {
    vec![]
}

#[derive(Debug, Clone, Default)]
pub struct EdgeTab {
    pub window_id: u32,
    pub tab_id: u32,
    pub title: String,
    pub url: String,
    pub last_accessed: u64,
}

pub fn get_edge_collections() -> Vec<EdgeCollection> {
    vec![]
}

#[derive(Debug, Clone, Default)]
pub struct EdgeCollection {
    pub name: String,
    pub created: u64,
    pub items: Vec<CollectionItem>,
}

#[derive(Debug, Clone, Default)]
pub struct CollectionItem {
    pub title: String,
    pub url: String,
    pub added: u64,
}

pub fn get_edge_reading_list() -> Vec<ReadingListItem> {
    vec![]
}

#[derive(Debug, Clone, Default)]
pub struct ReadingListItem {
    pub title: String,
    pub url: String,
    pub added: u64,
    pub read: bool,
}

fn edge_history_db_candidates() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_EDGE_HISTORY_DB") {
        return vec![PathBuf::from(path)];
    }
    if let Ok(user_profile) = env::var("USERPROFILE") {
        return vec![
            PathBuf::from(&user_profile)
                .join("AppData")
                .join("Local")
                .join("Microsoft")
                .join("Edge")
                .join("User Data")
                .join("Default")
                .join("History"),
            PathBuf::from("artifacts")
                .join("browser")
                .join("edge")
                .join("History"),
        ];
    }
    vec![PathBuf::from("artifacts")
        .join("browser")
        .join("edge")
        .join("History")]
}

fn edge_cookie_db_candidates() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_EDGE_COOKIES_DB") {
        return vec![PathBuf::from(path)];
    }
    if let Ok(user_profile) = env::var("USERPROFILE") {
        return vec![
            PathBuf::from(&user_profile)
                .join("AppData")
                .join("Local")
                .join("Microsoft")
                .join("Edge")
                .join("User Data")
                .join("Default")
                .join("Network")
                .join("Cookies"),
            PathBuf::from("artifacts")
                .join("browser")
                .join("edge")
                .join("Cookies"),
        ];
    }
    vec![PathBuf::from("artifacts")
        .join("browser")
        .join("edge")
        .join("Cookies")]
}

fn chrome_time_to_unix(raw: i64) -> Option<u64> {
    if raw <= 0 {
        return None;
    }
    // Chromium timestamp is microseconds since 1601-01-01.
    let seconds = raw / 1_000_000;
    if seconds < 11_644_473_600 {
        return None;
    }
    Some((seconds - 11_644_473_600) as u64)
}

fn map_download_state(state: i64) -> String {
    match state {
        0 => "in_progress",
        1 => "complete",
        2 => "cancelled",
        3 => "interrupted",
        _ => "unknown",
    }
    .to_string()
}

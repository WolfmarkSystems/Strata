use std::env;
use std::path::PathBuf;

use rusqlite::Connection;

pub fn get_firefox_downloads() -> Vec<FirefoxDownload> {
    let mut out = Vec::new();
    for db_path in firefox_places_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        // Mozilla stores download destination in moz_annos content for download-related entries.
        let query = r#"
SELECT
  COALESCE(p.url, ''),
  COALESCE(a.content, ''),
  COALESCE(v.visit_date, 0)
FROM moz_places p
LEFT JOIN moz_historyvisits v ON v.place_id = p.id
LEFT JOIN moz_annos a ON a.place_id = p.id
WHERE p.url LIKE 'http%' AND (a.content LIKE 'file:%' OR a.content LIKE '%\\%')
ORDER BY v.visit_date DESC
LIMIT 3000
"#;
        let Ok(mut stmt) = conn.prepare(query) else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            let file_raw: String = row.get(1).unwrap_or_default();
            Ok(FirefoxDownload {
                url: row.get::<_, String>(0).unwrap_or_default(),
                file_path: normalize_firefox_download_path(&file_raw),
                start_time: firefox_time_to_unix(row.get::<_, i64>(2).unwrap_or(0)).unwrap_or(0),
                end_time: None,
                size: 0,
            })
        });
        if let Ok(iter) = rows {
            for item in iter.flatten() {
                if !item.file_path.is_empty() {
                    out.push(item);
                }
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct FirefoxDownload {
    pub url: String,
    pub file_path: String,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub size: u64,
}

pub fn get_firefox_cookies() -> Vec<FirefoxCookie> {
    let mut out = Vec::new();
    for db_path in firefox_cookie_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT host, name, value, path, expiry FROM moz_cookies ORDER BY expiry DESC LIMIT 5000",
        ) else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            let exp: i64 = row.get(4).unwrap_or(0);
            Ok(FirefoxCookie {
                host: row.get::<_, String>(0).unwrap_or_default(),
                name: row.get::<_, String>(1).unwrap_or_default(),
                value: row.get::<_, String>(2).unwrap_or_default(),
                path: row.get::<_, String>(3).unwrap_or_default(),
                expiration: if exp > 0 { Some(exp as u64) } else { None },
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
pub struct FirefoxCookie {
    pub host: String,
    pub name: String,
    pub value: String,
    pub path: String,
    pub expiration: Option<u64>,
}

pub fn get_firefox_formhistory() -> Vec<FirefoxFormHistory> {
    let mut out = Vec::new();
    for db_path in firefox_formhistory_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT fieldname, value, timesUsed FROM moz_formhistory ORDER BY timesUsed DESC LIMIT 5000",
        ) else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            Ok(FirefoxFormHistory {
                field_name: row.get::<_, String>(0).unwrap_or_default(),
                value: row.get::<_, String>(1).unwrap_or_default(),
                times_used: row.get::<_, i64>(2).unwrap_or(0).max(0) as u32,
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
pub struct FirefoxFormHistory {
    pub field_name: String,
    pub value: String,
    pub times_used: u32,
}

fn firefox_places_db_candidates() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_FIREFOX_PLACES_DB") {
        return vec![PathBuf::from(path)];
    }
    let mut out = profile_candidates()
        .into_iter()
        .map(|p| p.join("places.sqlite"))
        .collect::<Vec<_>>();
    out.push(
        PathBuf::from("artifacts")
            .join("browser")
            .join("firefox")
            .join("places.sqlite"),
    );
    out
}

fn firefox_cookie_db_candidates() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_FIREFOX_COOKIES_DB") {
        return vec![PathBuf::from(path)];
    }
    let mut out = profile_candidates()
        .into_iter()
        .map(|p| p.join("cookies.sqlite"))
        .collect::<Vec<_>>();
    out.push(
        PathBuf::from("artifacts")
            .join("browser")
            .join("firefox")
            .join("cookies.sqlite"),
    );
    out
}

fn firefox_formhistory_db_candidates() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_FIREFOX_FORMHISTORY_DB") {
        return vec![PathBuf::from(path)];
    }
    let mut out = profile_candidates()
        .into_iter()
        .map(|p| p.join("formhistory.sqlite"))
        .collect::<Vec<_>>();
    out.push(
        PathBuf::from("artifacts")
            .join("browser")
            .join("firefox")
            .join("formhistory.sqlite"),
    );
    out
}

fn profile_candidates() -> Vec<PathBuf> {
    let Ok(user_profile) = env::var("USERPROFILE") else {
        return Vec::new();
    };
    let profiles_root = PathBuf::from(user_profile)
        .join("AppData")
        .join("Roaming")
        .join("Mozilla")
        .join("Firefox")
        .join("Profiles");
    let Ok(entries) = std::fs::read_dir(profiles_root) else {
        return Vec::new();
    };
    entries.flatten().map(|e| e.path()).collect()
}

fn firefox_time_to_unix(raw: i64) -> Option<u64> {
    if raw <= 0 {
        return None;
    }
    // Firefox visit_date is microseconds since Unix epoch.
    Some((raw / 1_000_000) as u64)
}

fn normalize_firefox_download_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("file://") {
        return trimmed.trim_start_matches("file://").replace('/', "\\");
    }
    trimmed.to_string()
}

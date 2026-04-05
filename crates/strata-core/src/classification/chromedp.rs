use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::Value;

pub fn get_chrome_downloads() -> Vec<DownloadEntry> {
    let mut out = Vec::new();
    for db_path in chrome_history_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let query = r#"
SELECT
  COALESCE(u.url, ''),
  COALESCE(d.target_path, ''),
  COALESCE(d.start_time, 0),
  COALESCE(d.end_time, 0),
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
            let end_raw: i64 = row.get(3).unwrap_or(0);
            Ok(DownloadEntry {
                url: row.get::<_, String>(0).unwrap_or_default(),
                file_path: row.get::<_, String>(1).unwrap_or_default(),
                start_time: chrome_time_to_unix(row.get::<_, i64>(2).unwrap_or(0)).unwrap_or(0),
                end_time: chrome_time_to_unix(end_raw),
                size: row.get::<_, i64>(4).unwrap_or(0).max(0) as u64,
                state: map_download_state(row.get::<_, i64>(5).unwrap_or(0)),
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
pub struct DownloadEntry {
    pub url: String,
    pub file_path: String,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub size: u64,
    pub state: String,
}

pub fn get_chrome_autofill() -> Vec<AutofillEntry> {
    let mut out = Vec::new();
    for db_path in chrome_webdata_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let Ok(mut stmt) =
            conn.prepare("SELECT name, value, count FROM autofill ORDER BY count DESC LIMIT 5000")
        else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            Ok(AutofillEntry {
                name: row.get::<_, String>(0).unwrap_or_default(),
                value: row.get::<_, String>(1).unwrap_or_default(),
                count: row.get::<_, i64>(2).unwrap_or(0).max(0) as u32,
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
pub struct AutofillEntry {
    pub name: String,
    pub value: String,
    pub count: u32,
}

pub fn get_chrome_extensions() -> Vec<ExtensionData> {
    let mut out = Vec::new();
    for root in chrome_extension_roots() {
        if !root.exists() {
            continue;
        }
        let Ok(ext_dirs) = strata_fs::read_dir(&root) else {
            continue;
        };
        for ext_dir in ext_dirs.flatten() {
            let ext_id = ext_dir.file_name().to_string_lossy().to_string();
            let ext_path = ext_dir.path();
            let Ok(version_dirs) = strata_fs::read_dir(&ext_path) else {
                continue;
            };
            for version_dir in version_dirs.flatten() {
                let manifest = version_dir.path().join("manifest.json");
                if !manifest.exists() {
                    continue;
                }
                if let Some(parsed) = parse_extension_manifest(&ext_id, &manifest) {
                    out.push(parsed);
                    break;
                }
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

fn parse_extension_manifest(ext_id: &str, manifest: &Path) -> Option<ExtensionData> {
    let data =
        super::scalpel::read_prefix(manifest, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let json: Value = serde_json::from_slice(&data).ok()?;
    let name = json
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let permissions = json
        .get("permissions")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    Some(ExtensionData {
        extension_id: ext_id.to_string(),
        name,
        permissions,
    })
}

#[derive(Debug, Clone, Default)]
pub struct ExtensionData {
    pub extension_id: String,
    pub name: String,
    pub permissions: Vec<String>,
}

fn chrome_history_db_candidates() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_CHROME_HISTORY_DB") {
        return vec![PathBuf::from(path)];
    }
    if let Ok(user_profile) = env::var("USERPROFILE") {
        return vec![
            PathBuf::from(&user_profile)
                .join("AppData")
                .join("Local")
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("History"),
            PathBuf::from("artifacts")
                .join("browser")
                .join("chrome")
                .join("History"),
        ];
    }
    vec![PathBuf::from("artifacts")
        .join("browser")
        .join("chrome")
        .join("History")]
}

fn chrome_webdata_db_candidates() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_CHROME_WEBDATA_DB") {
        return vec![PathBuf::from(path)];
    }
    if let Ok(user_profile) = env::var("USERPROFILE") {
        return vec![
            PathBuf::from(&user_profile)
                .join("AppData")
                .join("Local")
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Web Data"),
            PathBuf::from("artifacts")
                .join("browser")
                .join("chrome")
                .join("Web Data"),
        ];
    }
    vec![PathBuf::from("artifacts")
        .join("browser")
        .join("chrome")
        .join("Web Data")]
}

fn chrome_extension_roots() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_CHROME_EXTENSIONS_DIR") {
        return vec![PathBuf::from(path)];
    }
    if let Ok(user_profile) = env::var("USERPROFILE") {
        return vec![
            PathBuf::from(&user_profile)
                .join("AppData")
                .join("Local")
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Extensions"),
            PathBuf::from("artifacts")
                .join("browser")
                .join("chrome")
                .join("Extensions"),
        ];
    }
    vec![PathBuf::from("artifacts")
        .join("browser")
        .join("chrome")
        .join("Extensions")]
}

fn chrome_time_to_unix(raw: i64) -> Option<u64> {
    if raw <= 0 {
        return None;
    }
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

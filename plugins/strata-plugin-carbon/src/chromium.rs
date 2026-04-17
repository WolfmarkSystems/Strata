//! Chromium artifact parser — History, Login Data, Web Data, Favicons,
//! Network Action Predictor.
//!
//! Research reference: chromium_ripper (MIT) — studied; implementation
//! written independently from the Chromium source schema.
//!
//! Applies to Chrome, Edge, Brave, Opera, Vivaldi. The databases live
//! under profile directories matching:
//!
//! * `Google/Chrome/User Data/*/`
//! * `Microsoft/Edge/User Data/*/`
//! * `BraveSoftware/Brave-Browser/User Data/*/`
//!
//! WebKit epoch: microseconds since 1601-01-01 UTC. Conversion:
//! `Unix_us = WebKit_us - 11_644_473_600_000_000`.
//!
//! ## MITRE ATT&CK
//! * **T1217** — Browser Information Discovery (History, Favicons).
//! * **T1555.003** — Credentials from Web Browsers (Login Data; we
//!   record presence only — passwords are encrypted).
//! * **T1056.003** — Input Capture: Web Portal Capture (search terms,
//!   autofill).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// WebKit-to-Unix microsecond delta.
const WEBKIT_EPOCH_DELTA_US: i64 = 11_644_473_600_000_000;

/// Which Chromium artifact a record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChromiumArtifactType {
    HistoryUrl,
    HistoryDownload,
    HistorySearchTerm,
    LoginData,
    Autofill,
    Favicon,
    NetworkActionPredictor,
}

impl ChromiumArtifactType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChromiumArtifactType::HistoryUrl => "Chromium/History URL",
            ChromiumArtifactType::HistoryDownload => "Chromium/History Download",
            ChromiumArtifactType::HistorySearchTerm => "Chromium/History Search Term",
            ChromiumArtifactType::LoginData => "Chromium/Login Data",
            ChromiumArtifactType::Autofill => "Chromium/Autofill",
            ChromiumArtifactType::Favicon => "Chromium/Favicon",
            ChromiumArtifactType::NetworkActionPredictor => "Chromium/Network Action Predictor",
        }
    }

    pub fn mitre(&self) -> &'static str {
        match self {
            ChromiumArtifactType::HistoryUrl
            | ChromiumArtifactType::Favicon
            | ChromiumArtifactType::NetworkActionPredictor => "T1217",
            ChromiumArtifactType::HistoryDownload => "T1105",
            ChromiumArtifactType::HistorySearchTerm | ChromiumArtifactType::Autofill => "T1056.003",
            ChromiumArtifactType::LoginData => "T1555.003",
        }
    }

    pub fn forensic_value(&self) -> &'static str {
        match self {
            ChromiumArtifactType::HistoryDownload | ChromiumArtifactType::LoginData => "High",
            _ => "Medium",
        }
    }
}

/// One record from a Chromium artifact DB.
#[derive(Debug, Clone, PartialEq)]
pub enum ChromiumRecord {
    HistoryUrl(HistoryUrl),
    HistoryDownload(HistoryDownload),
    HistorySearchTerm(HistorySearchTerm),
    LoginData(LoginDataEntry),
    Autofill(AutofillEntry),
    Favicon(FaviconEntry),
    NetworkActionPredictor(NetworkActionPredictorEntry),
}

impl ChromiumRecord {
    pub fn artifact_type(&self) -> ChromiumArtifactType {
        match self {
            ChromiumRecord::HistoryUrl(_) => ChromiumArtifactType::HistoryUrl,
            ChromiumRecord::HistoryDownload(_) => ChromiumArtifactType::HistoryDownload,
            ChromiumRecord::HistorySearchTerm(_) => ChromiumArtifactType::HistorySearchTerm,
            ChromiumRecord::LoginData(_) => ChromiumArtifactType::LoginData,
            ChromiumRecord::Autofill(_) => ChromiumArtifactType::Autofill,
            ChromiumRecord::Favicon(_) => ChromiumArtifactType::Favicon,
            ChromiumRecord::NetworkActionPredictor(_) => {
                ChromiumArtifactType::NetworkActionPredictor
            }
        }
    }

    pub fn primary_time(&self) -> Option<DateTime<Utc>> {
        match self {
            ChromiumRecord::HistoryUrl(e) => e.last_visit_time,
            ChromiumRecord::HistoryDownload(e) => e.start_time,
            ChromiumRecord::HistorySearchTerm(_) => None,
            ChromiumRecord::LoginData(e) => e.date_last_used.or(e.date_created),
            ChromiumRecord::Autofill(e) => e.date_last_used.or(e.date_created),
            ChromiumRecord::Favicon(_) => None,
            ChromiumRecord::NetworkActionPredictor(_) => None,
        }
    }
}

/// History `urls` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryUrl {
    pub url: String,
    pub title: String,
    pub visit_count: i64,
    pub last_visit_time: Option<DateTime<Utc>>,
}

/// History `downloads` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryDownload {
    pub target_path: String,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub total_bytes: i64,
    pub danger_type: i64,
    pub tab_url: Option<String>,
    pub tab_referrer_url: Option<String>,
}

/// History `keyword_search_terms` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistorySearchTerm {
    pub term: String,
    pub url_id: i64,
}

/// Login Data `logins` row — password_value NOT captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginDataEntry {
    pub origin_url: String,
    pub username_value: String,
    pub date_created: Option<DateTime<Utc>>,
    pub date_last_used: Option<DateTime<Utc>>,
    pub times_used: i64,
}

/// Web Data `autofill` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutofillEntry {
    pub name: String,
    pub value: String,
    pub date_created: Option<DateTime<Utc>>,
    pub date_last_used: Option<DateTime<Utc>>,
    pub count: i64,
}

/// Favicons `icon_mapping` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaviconEntry {
    pub page_url: String,
}

/// `network_action_predictor.network_action_predictor` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkActionPredictorEntry {
    pub user_text: String,
    pub url: String,
}

/// Identify which Chromium DB a filename represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChromiumDb {
    History,
    LoginData,
    WebData,
    Favicons,
    NetworkActionPredictor,
}

impl ChromiumDb {
    pub fn from_path(path: &Path) -> Option<ChromiumDb> {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let full = path.to_string_lossy().to_ascii_lowercase();
        let is_chromium = full.contains("chrome/user data")
            || full.contains("chrome\\user data")
            || full.contains("edge/user data")
            || full.contains("edge\\user data")
            || full.contains("brave-browser/user data")
            || full.contains("brave-browser\\user data")
            || full.contains("vivaldi/user data")
            || full.contains("opera software");
        if !is_chromium {
            return None;
        }
        match name {
            "History" => Some(ChromiumDb::History),
            "Login Data" => Some(ChromiumDb::LoginData),
            "Web Data" => Some(ChromiumDb::WebData),
            "Favicons" => Some(ChromiumDb::Favicons),
            "Network Action Predictor" => Some(ChromiumDb::NetworkActionPredictor),
            _ => None,
        }
    }
}

/// Parse a Chromium database by classification. Empty vec for unknown
/// paths or unreadable files.
pub fn parse(path: &Path) -> Vec<ChromiumRecord> {
    match ChromiumDb::from_path(path) {
        Some(ChromiumDb::History) => parse_history(path),
        Some(ChromiumDb::LoginData) => parse_login_data(path),
        Some(ChromiumDb::WebData) => parse_web_data(path),
        Some(ChromiumDb::Favicons) => parse_favicons(path),
        Some(ChromiumDb::NetworkActionPredictor) => parse_network_action_predictor(path),
        None => Vec::new(),
    }
}

fn open_ro(path: &Path) -> Option<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()
}

fn decode_webkit(us: i64) -> Option<DateTime<Utc>> {
    if us == 0 {
        return None;
    }
    let unix_us = us.checked_sub(WEBKIT_EPOCH_DELTA_US)?;
    let secs = unix_us.div_euclid(1_000_000);
    let micros = unix_us.rem_euclid(1_000_000) as u32;
    DateTime::<Utc>::from_timestamp(secs, micros * 1_000)
}

fn parse_history(path: &Path) -> Vec<ChromiumRecord> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time ASC",
    ) {
        let rows = stmt.query_map([], |row| {
            Ok(HistoryUrl {
                url: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                title: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                visit_count: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                last_visit_time: row
                    .get::<_, Option<i64>>(3)?
                    .and_then(decode_webkit),
            })
        });
        if let Ok(rows) = rows {
            for r in rows.flatten() {
                out.push(ChromiumRecord::HistoryUrl(r));
            }
        }
    }
    if let Ok(mut stmt) = conn.prepare(
        "SELECT target_path, start_time, end_time, total_bytes, danger_type, \
                tab_url, tab_referrer_url FROM downloads ORDER BY start_time ASC",
    ) {
        let rows = stmt.query_map([], |row| {
            Ok(HistoryDownload {
                target_path: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                start_time: row.get::<_, Option<i64>>(1)?.and_then(decode_webkit),
                end_time: row.get::<_, Option<i64>>(2)?.and_then(decode_webkit),
                total_bytes: row.get::<_, Option<i64>>(3)?.unwrap_or(0),
                danger_type: row.get::<_, Option<i64>>(4)?.unwrap_or(0),
                tab_url: row.get::<_, Option<String>>(5)?,
                tab_referrer_url: row.get::<_, Option<String>>(6)?,
            })
        });
        if let Ok(rows) = rows {
            for r in rows.flatten() {
                out.push(ChromiumRecord::HistoryDownload(r));
            }
        }
    }
    if let Ok(mut stmt) = conn
        .prepare("SELECT term, url_id FROM keyword_search_terms ORDER BY url_id ASC")
    {
        let rows = stmt.query_map([], |row| {
            Ok(HistorySearchTerm {
                term: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                url_id: row.get::<_, Option<i64>>(1)?.unwrap_or(0),
            })
        });
        if let Ok(rows) = rows {
            for r in rows.flatten() {
                out.push(ChromiumRecord::HistorySearchTerm(r));
            }
        }
    }
    out
}

fn parse_login_data(path: &Path) -> Vec<ChromiumRecord> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let sql = "SELECT origin_url, username_value, date_created, date_last_used, times_used \
               FROM logins ORDER BY date_created ASC";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |row| {
        Ok(LoginDataEntry {
            origin_url: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
            username_value: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            date_created: row.get::<_, Option<i64>>(2)?.and_then(decode_webkit),
            date_last_used: row.get::<_, Option<i64>>(3)?.and_then(decode_webkit),
            times_used: row.get::<_, Option<i64>>(4)?.unwrap_or(0),
        })
    });
    let mut out = Vec::new();
    if let Ok(rows) = rows {
        for r in rows.flatten() {
            out.push(ChromiumRecord::LoginData(r));
        }
    }
    out
}

fn parse_web_data(path: &Path) -> Vec<ChromiumRecord> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let sql = "SELECT name, value, date_created, date_last_used, count \
               FROM autofill ORDER BY date_created ASC";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |row| {
        Ok(AutofillEntry {
            name: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
            value: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            date_created: row.get::<_, Option<i64>>(2)?.and_then(decode_webkit),
            date_last_used: row.get::<_, Option<i64>>(3)?.and_then(decode_webkit),
            count: row.get::<_, Option<i64>>(4)?.unwrap_or(0),
        })
    });
    let mut out = Vec::new();
    if let Ok(rows) = rows {
        for r in rows.flatten() {
            out.push(ChromiumRecord::Autofill(r));
        }
    }
    out
}

fn parse_favicons(path: &Path) -> Vec<ChromiumRecord> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let sql = "SELECT DISTINCT page_url FROM icon_mapping";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |row| {
        Ok(FaviconEntry {
            page_url: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
        })
    });
    let mut out = Vec::new();
    if let Ok(rows) = rows {
        for r in rows.flatten() {
            if !r.page_url.is_empty() {
                out.push(ChromiumRecord::Favicon(r));
            }
        }
    }
    out
}

fn parse_network_action_predictor(path: &Path) -> Vec<ChromiumRecord> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let sql = "SELECT user_text, url FROM network_action_predictor";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |row| {
        Ok(NetworkActionPredictorEntry {
            user_text: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
            url: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
        })
    });
    let mut out = Vec::new();
    if let Ok(rows) = rows {
        for r in rows.flatten() {
            out.push(ChromiumRecord::NetworkActionPredictor(r));
        }
    }
    out
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn in_chromium_tempdir(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile = dir
            .path()
            .join("Google/Chrome/User Data/Default");
        std::fs::create_dir_all(&profile).expect("mkdirs");
        let path = profile.join(name);
        (dir, path)
    }

    #[test]
    fn classify_path_recognises_canonical_layouts() {
        let p = Path::new("/Users/me/AppData/Local/Google/Chrome/User Data/Default/History");
        assert_eq!(ChromiumDb::from_path(p), Some(ChromiumDb::History));
        let p = Path::new("/Users/me/Microsoft/Edge/User Data/Default/Login Data");
        assert_eq!(ChromiumDb::from_path(p), Some(ChromiumDb::LoginData));
        let p = Path::new("/Users/me/Library/Application Support/BraveSoftware/Brave-Browser/User Data/Default/Favicons");
        assert_eq!(ChromiumDb::from_path(p), Some(ChromiumDb::Favicons));
        let p = Path::new("/no/match/History");
        assert!(ChromiumDb::from_path(p).is_none());
    }

    #[test]
    fn parse_history_extracts_urls_downloads_terms() {
        let (_dir, path) = in_chromium_tempdir("History");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER); \
             CREATE TABLE downloads (target_path TEXT, start_time INTEGER, end_time INTEGER, total_bytes INTEGER, danger_type INTEGER, tab_url TEXT, tab_referrer_url TEXT); \
             CREATE TABLE keyword_search_terms (term TEXT, url_id INTEGER);",
        )
        .expect("schema");
        // WebKit time for 2024-06-01 12:00:00 UTC:
        //   Unix 1_717_243_200 * 1e6 + 11_644_473_600_000_000 = 13_361_716_800_000_000
        let webkit_ts = 13_361_716_800_000_000_i64;
        conn.execute(
            "INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 3, ?1)",
            [webkit_ts],
        )
        .expect("urls");
        conn.execute(
            "INSERT INTO downloads VALUES ('C:\\Users\\alice\\file.exe', ?1, ?1, 12345, 0, 'https://x.test', 'https://ref.test')",
            [webkit_ts],
        )
        .expect("downloads");
        conn.execute(
            "INSERT INTO keyword_search_terms VALUES ('malware analysis', 1)",
            [],
        )
        .expect("search");
        drop(conn);

        let records = parse(&path);
        assert!(records.iter().any(|r| matches!(r, ChromiumRecord::HistoryUrl(h) if h.url == "https://example.com")));
        assert!(records.iter().any(|r| matches!(r, ChromiumRecord::HistoryDownload(d) if d.target_path.ends_with("file.exe"))));
        assert!(records.iter().any(|r| matches!(r, ChromiumRecord::HistorySearchTerm(t) if t.term == "malware analysis")));
        // Verify WebKit conversion.
        let url_ts = records.iter().find_map(|r| match r {
            ChromiumRecord::HistoryUrl(h) => h.last_visit_time.map(|d| d.timestamp()),
            _ => None,
        });
        assert_eq!(url_ts, Some(1_717_243_200));
    }

    #[test]
    fn parse_login_data_and_web_data() {
        let (_dir, path_login) = in_chromium_tempdir("Login Data");
        let conn = Connection::open(&path_login).expect("login");
        conn.execute_batch(
            "CREATE TABLE logins (origin_url TEXT, username_value TEXT, date_created INTEGER, date_last_used INTEGER, times_used INTEGER);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO logins VALUES ('https://bank.test', 'alice@example.com', 13361716800000000, 13361716800000000, 7)",
            [],
        )
        .expect("insert");
        drop(conn);
        let records = parse(&path_login);
        assert!(records.iter().any(|r| matches!(r, ChromiumRecord::LoginData(l) if l.username_value == "alice@example.com")));

        let (_dir2, path_web) = in_chromium_tempdir("Web Data");
        let conn = Connection::open(&path_web).expect("web");
        conn.execute_batch(
            "CREATE TABLE autofill (name TEXT, value TEXT, date_created INTEGER, date_last_used INTEGER, count INTEGER);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO autofill VALUES ('email', 'alice@example.com', 13361716800000000, 13361716800000000, 3)",
            [],
        )
        .expect("insert");
        drop(conn);
        let records = parse(&path_web);
        assert!(records.iter().any(|r| matches!(r, ChromiumRecord::Autofill(a) if a.name == "email")));
    }

    #[test]
    fn parse_favicons_extracts_distinct_page_urls() {
        let (_dir, path) = in_chromium_tempdir("Favicons");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE icon_mapping (page_url TEXT);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO icon_mapping VALUES ('https://example.com'), ('https://example.com'), ('https://other.test')",
            [],
        )
        .expect("insert");
        drop(conn);
        let records = parse(&path);
        let urls: Vec<&str> = records
            .iter()
            .filter_map(|r| match r {
                ChromiumRecord::Favicon(f) => Some(f.page_url.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn decode_webkit_handles_edge_cases() {
        assert!(decode_webkit(0).is_none());
        // WebKit time for 2024-06-01 12:00:00 UTC.
        let d = decode_webkit(13_361_716_800_000_000).expect("ok");
        assert_eq!(d.timestamp(), 1_717_243_200);
    }

    #[test]
    fn mitre_mapping_per_type() {
        assert_eq!(ChromiumArtifactType::HistoryUrl.mitre(), "T1217");
        assert_eq!(ChromiumArtifactType::LoginData.mitre(), "T1555.003");
        assert_eq!(ChromiumArtifactType::HistorySearchTerm.mitre(), "T1056.003");
        assert_eq!(ChromiumArtifactType::HistoryDownload.mitre(), "T1105");
    }
}

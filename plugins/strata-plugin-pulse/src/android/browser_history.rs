//! BrowserHistory — Chromium-family browser URL history on Android.
//!
//! ALEAPP references: `scripts/artifacts/browserHistory.py`,
//! `scripts/artifacts/chromeHistory.py`. All Chromium-derived
//! browsers on Android (Chrome, Samsung Internet, Brave, Edge) keep a
//! `History` SQLite DB with the standard Chromium schema:
//!
//! ```sql
//! CREATE TABLE urls (
//!   id INTEGER PRIMARY KEY,
//!   url LONGVARCHAR,
//!   title LONGVARCHAR,
//!   visit_count INTEGER,
//!   typed_count INTEGER,
//!   last_visit_time INTEGER,  -- Chrome/WebKit microseconds
//!   hidden INTEGER
//! );
//!
//! CREATE TABLE visits (
//!   id INTEGER PRIMARY KEY,
//!   url INTEGER,
//!   visit_time INTEGER,
//!   from_visit INTEGER,
//!   transition INTEGER,
//!   segment_id INTEGER,
//!   visit_duration INTEGER
//! );
//! ```
//!
//! Pulse reads `urls` joined to `visits` so each forensic record is
//! one visit with its accompanying URL + title.

use crate::android::helpers::{build_record, chrome_to_unix, open_sqlite_ro, table_exists};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["/history", "\\history", "browserhistory.db"];

/// URL host fragments commonly used by anonymity services; any URL
/// containing one of these gets flagged as suspicious.
const SUSPICIOUS_HOSTS: &[&str] = &[
    ".onion",
    "torproject.org",
    "duckduckgo.com",
    "protonmail",
    "tutanota",
    "ahmia.fi",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "urls") {
        return Vec::new();
    }
    if table_exists(&conn, "visits") {
        read_joined(&conn, path)
    } else {
        read_urls_only(&conn, path)
    }
}

fn read_joined(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = r#"
        SELECT u.url, u.title, v.visit_time, u.visit_count
        FROM visits v
        JOIN urls u ON u.id = v.url
        ORDER BY v.visit_time DESC
        LIMIT 20000
    "#;
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    build_visit_records(rows.flatten().collect(), path)
}

fn read_urls_only(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = r#"
        SELECT url, title, last_visit_time, visit_count
        FROM urls
        ORDER BY last_visit_time DESC
        LIMIT 20000
    "#;
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    build_visit_records(rows.flatten().collect(), path)
}

/// One row pulled from the urls/visits join — `(url, title, time_us, visit_count)`.
type VisitRow = (Option<String>, Option<String>, Option<i64>, Option<i64>);

fn build_visit_records(rows: Vec<VisitRow>, path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    for (url, title, time_us, count) in rows {
        let url = url.unwrap_or_default();
        if url.is_empty() {
            continue;
        }
        let title = title.unwrap_or_default();
        let ts = time_us.and_then(chrome_to_unix);
        let url_lc = url.to_lowercase();
        let suspicious = SUSPICIOUS_HOSTS.iter().any(|h| url_lc.contains(h));
        let detail = format!(
            "Visited URL '{}' title='{}' visit_count={}",
            url,
            title,
            count.unwrap_or(0)
        );
        let forensic_value = if suspicious {
            ForensicValue::High
        } else {
            ForensicValue::Medium
        };
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Android Browser History",
            format!("URL: {}", url),
            detail,
            path,
            ts,
            forensic_value,
            suspicious,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn webkit_us(unix_sec: i64) -> i64 {
        (unix_sec + 11_644_473_600) * 1_000_000
    }

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url LONGVARCHAR,
                title LONGVARCHAR,
                visit_count INTEGER,
                typed_count INTEGER,
                last_visit_time INTEGER,
                hidden INTEGER
            );
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY,
                url INTEGER,
                visit_time INTEGER,
                from_visit INTEGER,
                transition INTEGER,
                segment_id INTEGER,
                visit_duration INTEGER
            );
            "#,
        )
        .unwrap();
        let t1 = webkit_us(1_609_459_200);
        let t2 = webkit_us(1_609_459_300);
        c.execute(
            "INSERT INTO urls VALUES (1,'https://example.com','Example',3,1,?1,0)",
            [t1],
        )
        .unwrap();
        c.execute(
            "INSERT INTO urls VALUES (2,'http://exampleonion.onion','Hidden',1,0,?1,0)",
            [t2],
        )
        .unwrap();
        c.execute(
            "INSERT INTO visits VALUES (1,1,?1,0,805306368,0,0)",
            [t1],
        )
        .unwrap();
        c.execute(
            "INSERT INTO visits VALUES (2,2,?1,0,805306368,0,0)",
            [t2],
        )
        .unwrap();
        tmp
    }

    #[test]
    fn reads_visits_joined_to_urls() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|c| c.category == ArtifactCategory::WebActivity));
    }

    #[test]
    fn suspicious_hosts_flagged() {
        let db = make_db();
        let r = parse(db.path());
        let onion = r.iter().find(|c| c.title.contains(".onion")).unwrap();
        assert!(onion.is_suspicious);
        assert_eq!(onion.forensic_value, ForensicValue::High);
    }

    #[test]
    fn chrome_timestamps_converted() {
        let db = make_db();
        let r = parse(db.path());
        let ex = r.iter().find(|c| c.title.contains("example.com")).unwrap();
        assert_eq!(ex.timestamp, Some(1_609_459_200));
    }

    #[test]
    fn reads_urls_only_when_visits_missing() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url LONGVARCHAR,
                title LONGVARCHAR,
                visit_count INTEGER,
                typed_count INTEGER,
                last_visit_time INTEGER,
                hidden INTEGER
            );
            "#,
        )
        .unwrap();
        let t = webkit_us(1_609_459_500);
        c.execute(
            "INSERT INTO urls VALUES (1,'https://x.com','X',1,0,?1,0)",
            [t],
        )
        .unwrap();
        drop(c);
        let r = parse(tmp.path());
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].timestamp, Some(1_609_459_500));
    }
}

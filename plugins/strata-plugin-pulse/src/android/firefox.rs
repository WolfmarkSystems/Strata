//! Firefox — Android browser history and bookmark extraction.
//!
//! ALEAPP reference: `scripts/artifacts/firefox.py`. Source path:
//! `/data/data/org.mozilla.firefox/files/places.sqlite`.
//!
//! Key tables: `moz_places`, `moz_historyvisits`, `moz_bookmarks`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "org.mozilla.firefox/files/places.sqlite",
    "org.mozilla.firefox/databases/places.sqlite",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "moz_places") {
        out.extend(read_history(&conn, path));
    }
    if table_exists(&conn, "moz_bookmarks") {
        out.extend(read_bookmarks(&conn, path));
    }
    out
}

fn read_history(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    // moz_historyvisits stores visit_date as PRTime (microseconds since epoch)
    let sql = "SELECT p.url, p.title, v.visit_date, p.visit_count \
               FROM moz_places p \
               JOIN moz_historyvisits v ON p.id = v.place_id \
               ORDER BY v.visit_date DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        // Fallback: if no visits table, just read places
        Err(_) => return read_places_only(conn, path),
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
    let mut out = Vec::new();
    for (url, title, visit_us, visit_count) in rows.flatten() {
        let url = url.unwrap_or_else(|| "(unknown)".to_string());
        let title = title.unwrap_or_default();
        // PRTime: microseconds since epoch
        let ts = visit_us.map(|us| us / 1_000_000);
        let count = visit_count.unwrap_or(0);
        let display = if title.is_empty() { &url } else { &title };
        let title_str = format!("Firefox: {}", display);
        let detail = format!(
            "Firefox history url='{}' title='{}' visit_count={}",
            url, title, count
        );
        let suspicious = is_suspicious_url(&url);
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Firefox History",
            title_str,
            detail,
            path,
            ts,
            if suspicious { ForensicValue::Critical } else { ForensicValue::Medium },
            suspicious,
        ));
    }
    out
}

fn read_places_only(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT url, title, visit_count, last_visit_date \
               FROM moz_places WHERE visit_count > 0 \
               ORDER BY last_visit_date DESC LIMIT 10000";
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
    let mut out = Vec::new();
    for (url, title, count, last_visit) in rows.flatten() {
        let url = url.unwrap_or_else(|| "(unknown)".to_string());
        let title = title.unwrap_or_default();
        let ts = last_visit.map(|us| us / 1_000_000);
        let display = if title.is_empty() { &url } else { &title };
        let title_str = format!("Firefox: {}", display);
        let detail = format!(
            "Firefox history url='{}' title='{}' visit_count={}",
            url, title, count.unwrap_or(0)
        );
        let suspicious = is_suspicious_url(&url);
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Firefox History",
            title_str,
            detail,
            path,
            ts,
            if suspicious { ForensicValue::Critical } else { ForensicValue::Medium },
            suspicious,
        ));
    }
    out
}

fn read_bookmarks(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT b.title, p.url, b.dateAdded \
               FROM moz_bookmarks b \
               LEFT JOIN moz_places p ON b.fk = p.id \
               WHERE b.type = 1 \
               ORDER BY b.dateAdded DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (title, url, date_added) in rows.flatten() {
        let title = title.unwrap_or_else(|| "(untitled)".to_string());
        let url = url.unwrap_or_else(|| "(no url)".to_string());
        let ts = date_added.map(|us| us / 1_000_000);
        let title_str = format!("Firefox bookmark: {}", title);
        let detail = format!("Firefox bookmark title='{}' url='{}'", title, url);
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Firefox Bookmark",
            title_str,
            detail,
            path,
            ts,
            ForensicValue::Low,
            false,
        ));
    }
    out
}

fn is_suspicious_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains(".onion")
        || lower.contains("tor2web")
        || lower.contains("pastebin.com/raw")
        || lower.contains("mega.nz")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_date INTEGER
            );
            INSERT INTO moz_places VALUES(1,'https://example.com','Example',5,1609459200000000);
            INSERT INTO moz_places VALUES(2,'https://secret.onion/page','Hidden Service',1,1609459300000000);
            INSERT INTO moz_places VALUES(3,'https://news.com','Daily News',10,1609459400000000);
            CREATE TABLE moz_historyvisits (
                id INTEGER PRIMARY KEY,
                place_id INTEGER,
                visit_date INTEGER
            );
            INSERT INTO moz_historyvisits VALUES(1,1,1609459200000000);
            INSERT INTO moz_historyvisits VALUES(2,2,1609459300000000);
            INSERT INTO moz_historyvisits VALUES(3,3,1609459400000000);
            CREATE TABLE moz_bookmarks (
                id INTEGER PRIMARY KEY,
                fk INTEGER,
                title TEXT,
                type INTEGER,
                dateAdded INTEGER
            );
            INSERT INTO moz_bookmarks VALUES(1,1,'Example Bookmark',1,1609459200000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_history_and_bookmarks() {
        let db = make_db();
        let r = parse(db.path());
        let hist: Vec<_> = r.iter().filter(|a| a.subcategory == "Firefox History").collect();
        let bkmk: Vec<_> = r.iter().filter(|a| a.subcategory == "Firefox Bookmark").collect();
        assert_eq!(hist.len(), 3);
        assert_eq!(bkmk.len(), 1);
    }

    #[test]
    fn onion_url_is_flagged_suspicious() {
        let db = make_db();
        let r = parse(db.path());
        let onion = r.iter().find(|a| a.detail.contains(".onion")).unwrap();
        assert!(onion.is_suspicious);
        assert!(matches!(onion.forensic_value, ForensicValue::Critical));
    }

    #[test]
    fn url_and_title_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("url='https://example.com'")));
        assert!(r.iter().any(|a| a.detail.contains("title='Daily News'")));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}

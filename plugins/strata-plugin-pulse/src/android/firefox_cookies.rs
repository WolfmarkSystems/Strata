//! Firefox Cookies — Android Firefox cookie extraction.
//!
//! ALEAPP reference: `scripts/artifacts/firefoxCookies.py`. Source path:
//! `/data/data/org.mozilla.firefox/files/cookies.sqlite`.
//!
//! Key table: `moz_cookies`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["org.mozilla.firefox/files/cookies.sqlite"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "moz_cookies") {
        return Vec::new();
    }
    read_cookies(&conn, path)
}

fn read_cookies(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT host, name, value, expiry, creationTime, \
               lastAccessed, isSecure, isHttpOnly \
               FROM moz_cookies ORDER BY lastAccessed DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (host, name, value, _expiry, creation, _last, secure, httponly) in rows.flatten() {
        let host = host.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let val = value.unwrap_or_default();
        // creationTime is PRTime (microseconds since epoch)
        let ts = creation.map(|us| us / 1_000_000);
        let secure_flag = secure.unwrap_or(0) != 0;
        let http_flag = httponly.unwrap_or(0) != 0;
        let title = format!("Firefox cookie: {} @ {}", name, host);
        let detail = format!(
            "Firefox cookie host='{}' name='{}' value='{}' secure={} httpOnly={}",
            host, name, val, secure_flag, http_flag
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Firefox Cookie",
            title,
            detail,
            path,
            ts,
            ForensicValue::Low,
            false,
        ));
    }
    out
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
            CREATE TABLE moz_cookies (
                id INTEGER PRIMARY KEY,
                host TEXT,
                name TEXT,
                value TEXT,
                expiry INTEGER,
                creationTime INTEGER,
                lastAccessed INTEGER,
                isSecure INTEGER,
                isHttpOnly INTEGER
            );
            INSERT INTO moz_cookies VALUES(1,'.example.com','session_id','abc123',9999999999,1609459200000000,1609459300000000,1,1);
            INSERT INTO moz_cookies VALUES(2,'.tracker.com','_ga','GA1.2.xxx',9999999999,1609459400000000,1609459500000000,0,0);
            INSERT INTO moz_cookies VALUES(3,'.news.com','prefs','dark',9999999999,1609459600000000,1609459700000000,0,0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_cookies() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Firefox Cookie"));
    }

    #[test]
    fn host_and_name_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("session_id") && a.title.contains(".example.com")));
    }

    #[test]
    fn secure_flag_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let s = r.iter().find(|a| a.detail.contains(".example.com")).unwrap();
        assert!(s.detail.contains("secure=true"));
        assert!(s.detail.contains("httpOnly=true"));
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

//! Chrome cookies — `Cookies` SQLite database.
//!
//! ALEAPP reference: `scripts/artifacts/chromeCookies.py`. Source path:
//! `/data/data/com.android.chrome/app_chrome/Default/Cookies` with the
//! `cookies` table:
//!
//! - `host_key`
//! - `name`
//! - `value` — typically empty on disk because the actual value is
//!   stored in `encrypted_value` (encrypted via the OS-level Chrome
//!   key). Pulse records the host/name pair regardless.
//! - `creation_utc` / `expires_utc` / `last_access_utc` — Chrome
//!   microseconds since 1601.
//! - `is_secure` / `is_httponly`

use crate::android::helpers::{
    build_record, chrome_to_unix, column_exists, open_sqlite_ro, table_exists,
};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["/cookies", "\\cookies"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "cookies") {
        return Vec::new();
    }
    read(&conn, path)
}

fn read(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_host = column_exists(conn, "cookies", "host_key");
    let has_name = column_exists(conn, "cookies", "name");
    if !(has_host && has_name) {
        return Vec::new();
    }
    let has_creation = column_exists(conn, "cookies", "creation_utc");
    let has_secure = column_exists(conn, "cookies", "is_secure");
    let has_http = column_exists(conn, "cookies", "is_httponly");

    let sql = format!(
        "SELECT host_key, name, {}, {}, {} FROM cookies LIMIT 50000",
        if has_creation { "creation_utc" } else { "0" },
        if has_secure { "is_secure" } else { "0" },
        if has_http { "is_httponly" } else { "0" }
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (host, name, creation_us, secure, http) in rows.flatten() {
        let host = host.unwrap_or_default();
        let name = name.unwrap_or_default();
        if host.is_empty() && name.is_empty() {
            continue;
        }
        let ts = creation_us.and_then(chrome_to_unix);
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Android Chrome Cookie",
            format!("Cookie: {} ({})", host, name),
            format!(
                "Chrome cookie host='{}' name='{}' secure={} httponly={}",
                host,
                name,
                secure.unwrap_or(0) != 0,
                http.unwrap_or(0) != 0
            ),
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

    fn webkit_us(unix_sec: i64) -> i64 {
        (unix_sec + 11_644_473_600) * 1_000_000
    }

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE cookies (
                creation_utc INTEGER,
                host_key TEXT,
                name TEXT,
                value TEXT,
                is_secure INTEGER,
                is_httponly INTEGER
            );
            "#,
        )
        .unwrap();
        let t = webkit_us(1_609_459_200);
        c.execute(
            "INSERT INTO cookies VALUES (?1,'.example.com','sessionid','',1,1)",
            [t],
        )
        .unwrap();
        c.execute(
            "INSERT INTO cookies VALUES (?1,'.google.com','NID','',1,0)",
            [t],
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_cookies() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn host_and_name_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|x| x.title.contains(".example.com") && x.title.contains("sessionid")));
    }

    #[test]
    fn flags_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let session = r.iter().find(|x| x.title.contains("sessionid")).unwrap();
        assert!(session.detail.contains("secure=true"));
        assert!(session.detail.contains("httponly=true"));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE foo(x INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}

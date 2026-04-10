//! CallLogs — Android call history.
//!
//! ALEAPP reference: `scripts/artifacts/calllogs.py`. The source is
//! `/data/data/com.android.providers.contacts/databases/calllog.db`
//! (or `contacts2.db` on older devices) and the table of interest is
//! `calls`.
//!
//! Schema (Android 11+):
//! ```sql
//! CREATE TABLE calls (
//!   _id INTEGER PRIMARY KEY,
//!   number TEXT,
//!   date INTEGER,           -- ms since epoch
//!   duration INTEGER,       -- seconds
//!   type INTEGER,           -- 1=incoming 2=outgoing 3=missed ...
//!   name TEXT,
//!   geocoded_location TEXT,
//!   countryiso TEXT,
//!   presentation INTEGER
//! );
//! ```

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["calllog.db", "calls.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "calls") {
        return Vec::new();
    }
    read_calls(&conn, path)
}

fn map_call_type(code: i64) -> &'static str {
    match code {
        1 => "incoming",
        2 => "outgoing",
        3 => "missed",
        4 => "voicemail",
        5 => "rejected",
        6 => "blocked",
        7 => "answered_externally",
        _ => "unknown",
    }
}

fn read_calls(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_geo = column_exists(conn, "calls", "geocoded_location");
    let has_name = column_exists(conn, "calls", "name");

    let mut sql = String::from("SELECT number, date, duration, type");
    if has_name {
        sql.push_str(", name");
    } else {
        sql.push_str(", NULL");
    }
    if has_geo {
        sql.push_str(", geocoded_location");
    } else {
        sql.push_str(", NULL");
    }
    sql.push_str(" FROM calls ORDER BY date DESC LIMIT 10000");

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for (number, date_ms, duration, type_code, name, geo) in rows.flatten() {
        let number = number.unwrap_or_else(|| "(withheld)".to_string());
        let duration = duration.unwrap_or(0);
        let kind = map_call_type(type_code.unwrap_or(0));
        let ts = date_ms.and_then(unix_ms_to_i64);
        let mut detail = format!(
            "Android call {} — direction={} duration={}s",
            number, kind, duration
        );
        if let Some(n) = name.filter(|n| !n.is_empty()) {
            detail.push_str(&format!(" name='{}'", n));
        }
        if let Some(g) = geo.filter(|g| !g.is_empty()) {
            detail.push_str(&format!(" geo='{}'", g));
        }
        let title = format!("Call {}: {}", kind, number);
        out.push(build_record(
            ArtifactCategory::Communications,
            "Android Call Log",
            title,
            detail,
            path,
            ts,
            ForensicValue::High,
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
            CREATE TABLE calls (
                _id INTEGER PRIMARY KEY,
                number TEXT,
                date INTEGER,
                duration INTEGER,
                type INTEGER,
                name TEXT,
                geocoded_location TEXT
            );
            INSERT INTO calls VALUES(1,'+15551234567',1609459200000,60,1,'Alice','San Jose, CA');
            INSERT INTO calls VALUES(2,'+15557654321',1609459300000,0,3,'Bob',NULL);
            INSERT INTO calls VALUES(3,'',1609459400000,15,2,NULL,NULL);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_calls() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|c| c.category == ArtifactCategory::Communications));
    }

    #[test]
    fn directions_are_mapped() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|c| c.title.contains("incoming")));
        assert!(r.iter().any(|c| c.title.contains("missed")));
        assert!(r.iter().any(|c| c.title.contains("outgoing")));
    }

    #[test]
    fn detail_captures_duration_name_geo() {
        let db = make_db();
        let r = parse(db.path());
        let alice = r.iter().find(|c| c.title.contains("+15551234567")).unwrap();
        assert!(alice.detail.contains("duration=60s"));
        assert!(alice.detail.contains("name='Alice'"));
        assert!(alice.detail.contains("geo='San Jose, CA'"));
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

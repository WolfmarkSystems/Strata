//! Keyboard cache — Gboard / SwiftKey learned-words history.
//!
//! ALEAPP reference: `scripts/artifacts/gboardKeyboardCache.py`,
//! `scripts/artifacts/swiftkey_keyboard.py`. Common database paths:
//!
//! - `/data/data/com.google.android.inputmethod.latin/databases/trainingcache3.db`
//!   with the `training_input_events_table` table.
//! - `/data/data/com.touchtype.swiftkey/files/storage/dynamic.lm` (binary).
//!
//! Pulse parses the Gboard SQLite form. Each cached word becomes one
//! record — keyboard caches frequently leak passwords and PII because
//! the predictive engine remembers what the user typed but never sent.

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "trainingcache3.db",
    "trainingcache.db",
    "training_input_events.db",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if table_exists(&conn, "training_input_events_table") {
        return read(&conn, path, "training_input_events_table");
    }
    if table_exists(&conn, "training_input_events") {
        return read(&conn, path, "training_input_events");
    }
    Vec::new()
}

fn read(conn: &Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let has_text = column_exists(conn, table, "_payload");
    let has_text2 = column_exists(conn, table, "input_text");
    let text_col = if has_text {
        "_payload"
    } else if has_text2 {
        "input_text"
    } else {
        return Vec::new();
    };
    let has_ts = column_exists(conn, table, "_timestamp");
    let sql = format!(
        "SELECT {}, {} FROM {} ORDER BY {} DESC LIMIT 10000",
        text_col,
        if has_ts { "_timestamp" } else { "0" },
        table,
        if has_ts { "_timestamp" } else { "rowid" }
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (text, ts_ms) in rows.flatten() {
        let text = text.unwrap_or_default();
        if text.trim().is_empty() {
            continue;
        }
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = text.chars().take(120).collect();
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Android Keyboard Cache",
            format!("Typed: {}", preview),
            format!("Keyboard cache entry text='{}'", text),
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
            CREATE TABLE training_input_events_table (
                _id INTEGER PRIMARY KEY,
                _payload TEXT,
                _timestamp INTEGER
            );
            INSERT INTO training_input_events_table VALUES (1,'where is my package',1609459200000);
            INSERT INTO training_input_events_table VALUES (2,'password is hunter2',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_entries() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn payload_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|x| x.detail.contains("hunter2")));
    }

    #[test]
    fn forensic_value_is_high() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().all(|x| x.forensic_value == ForensicValue::High));
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

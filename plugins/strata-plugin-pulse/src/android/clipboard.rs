//! Clipboard — Gboard / clipboard manager history.
//!
//! ALEAPP reference: `scripts/artifacts/gboardClipboard.py`. Source path:
//! `/data/data/com.google.android.inputmethod.latin/databases/gboard_clipboard.db`
//! with the `clips` table:
//!
//! - `_id`
//! - `text` — clipboard payload
//! - `timestamp` (Unix milliseconds)
//! - `is_pinned`
//!
//! Clipboard contents are forensically significant — passwords, 2FA
//! codes, addresses, and account numbers all flow through here.

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["gboard_clipboard.db", "clipboard.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "clips") {
        return Vec::new();
    }
    read_clips(&conn, path)
}

fn read_clips(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_text = column_exists(conn, "clips", "text");
    if !has_text {
        return Vec::new();
    }
    let has_ts = column_exists(conn, "clips", "timestamp");
    let has_pinned = column_exists(conn, "clips", "is_pinned");

    let sql = format!(
        "SELECT text, {}, {} FROM clips ORDER BY {} DESC LIMIT 5000",
        if has_ts { "timestamp" } else { "0" },
        if has_pinned { "is_pinned" } else { "0" },
        if has_ts { "timestamp" } else { "_id" }
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (text, ts_ms, pinned) in rows.flatten() {
        let text = text.unwrap_or_default();
        if text.is_empty() {
            continue;
        }
        let preview: String = text.chars().take(120).collect();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let pinned_flag = pinned.unwrap_or(0) != 0;
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Android Clipboard",
            format!("Clip: {}", preview),
            format!(
                "Clipboard text='{}' pinned={}",
                text, pinned_flag
            ),
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
            CREATE TABLE clips (_id INTEGER PRIMARY KEY, text TEXT, timestamp INTEGER, is_pinned INTEGER);
            INSERT INTO clips VALUES (1,'my password is hunter2',1609459200000,0);
            INSERT INTO clips VALUES (2,'2FA code: 123456',1609459300000,1);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn reads_two_clips() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|x| x.subcategory == "Android Clipboard"));
    }

    #[test]
    fn pinned_flag_appears_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let twofa = r.iter().find(|x| x.detail.contains("123456")).unwrap();
        assert!(twofa.detail.contains("pinned=true"));
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

//! Gmail — Android Gmail app database.
//!
//! ALEAPP reference: `scripts/artifacts/gmail.py`. Source path:
//! `/data/data/com.google.android.gm/databases/mailstore.<account>.db`
//! with the `messages` table. Columns of interest:
//!
//! - `_id`
//! - `messageId` (opaque Gmail-assigned ID)
//! - `fromAddress` / `toAddresses`
//! - `subject`
//! - `dateSentMs` / `dateReceivedMs`
//! - `snippet` (first ~120 chars of body)

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["mailstore.", "gmail", "bigtopandroidstorage"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "messages") {
        return Vec::new();
    }
    read_messages(&conn, path)
}

fn read_messages(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_from = column_exists(conn, "messages", "fromAddress");
    let has_to = column_exists(conn, "messages", "toAddresses");
    let has_subject = column_exists(conn, "messages", "subject");
    let has_snippet = column_exists(conn, "messages", "snippet");
    let has_date = column_exists(conn, "messages", "dateSentMs")
        || column_exists(conn, "messages", "dateReceivedMs");

    if !(has_from || has_to || has_subject) {
        return Vec::new();
    }

    let ts_col = if column_exists(conn, "messages", "dateSentMs") {
        "dateSentMs"
    } else if column_exists(conn, "messages", "dateReceivedMs") {
        "dateReceivedMs"
    } else {
        "0"
    };

    let mut cols = Vec::new();
    cols.push(if has_from { "fromAddress" } else { "NULL" });
    cols.push(if has_to { "toAddresses" } else { "NULL" });
    cols.push(if has_subject { "subject" } else { "NULL" });
    cols.push(if has_snippet { "snippet" } else { "NULL" });
    cols.push(if has_date { ts_col } else { "0" });

    let sql = format!(
        "SELECT {} FROM messages ORDER BY {} DESC LIMIT 20000",
        cols.join(", "),
        ts_col
    );

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for (from, to, subject, snippet, ts_ms) in rows.flatten() {
        let from = from.unwrap_or_default();
        let to = to.unwrap_or_default();
        let subject = subject.unwrap_or_default();
        let snippet = snippet.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!(
            "Gmail: {}",
            if !subject.is_empty() {
                subject.clone()
            } else {
                "(no subject)".to_string()
            }
        );
        let detail = format!(
            "Gmail message from='{}' to='{}' subject='{}' snippet='{}'",
            from, to, subject, snippet
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Android Gmail",
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
            CREATE TABLE messages (
                _id INTEGER PRIMARY KEY,
                fromAddress TEXT,
                toAddresses TEXT,
                subject TEXT,
                snippet TEXT,
                dateSentMs INTEGER
            );
            INSERT INTO messages VALUES (1,'alice@example.com','bob@example.com','Meeting','See you at 3',1609459200000);
            INSERT INTO messages VALUES (2,'eve@evilcorp.com','victim@example.com','Invoice','Urgent wire transfer',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_messages() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|m| m.subcategory == "Android Gmail"));
    }

    #[test]
    fn subject_appears_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|m| m.title == "Gmail: Meeting"));
        assert!(r.iter().any(|m| m.title == "Gmail: Invoice"));
    }

    #[test]
    fn from_and_snippet_captured_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let urgent = r
            .iter()
            .find(|m| m.detail.contains("eve@evilcorp.com"))
            .unwrap();
        assert!(urgent.detail.contains("Urgent wire transfer"));
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

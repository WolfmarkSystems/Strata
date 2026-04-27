//! Samsung Notes — Android Samsung note extraction.
//!
//! ALEAPP reference: `scripts/artifacts/SamsungNotes.py`. Source path:
//! `/data/data/com.samsung.android.app.notes/databases/notes_db`.
//!
//! Key table: `note` or `note_meta`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.samsung.android.app.notes/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if table_exists(&conn, "note") {
        read_notes(&conn, path)
    } else if table_exists(&conn, "note_meta") {
        read_notes_meta(&conn, path)
    } else {
        Vec::new()
    }
}

fn read_notes(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT title, content_text, created_time, modified_time, \
               is_trashed \
               FROM note \
               ORDER BY modified_time DESC LIMIT 5000";
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (title, content, created, modified, trashed) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let body = content.unwrap_or_default();
        let ts = modified
            .and_then(unix_ms_to_i64)
            .or(created.and_then(unix_ms_to_i64));
        let is_trashed = trashed.unwrap_or(0) != 0;
        let preview: String = body.chars().take(120).collect();
        let display = if title_str == "(untitled)" {
            &preview
        } else {
            &title_str
        };
        let title_out = format!("Samsung Note: {}", display);
        let mut detail = format!("Samsung Notes title='{}' body='{}'", title_str, body);
        if is_trashed {
            detail.push_str(" trashed=true");
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Samsung Notes",
            title_out,
            detail,
            path,
            ts,
            ForensicValue::Medium,
            is_trashed, // Trashed notes are forensically interesting
        ));
    }
    out
}

fn read_notes_meta(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT title, created_at, updated_at \
               FROM note_meta \
               ORDER BY updated_at DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
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
    for (title, created, updated) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let ts = updated
            .and_then(unix_ms_to_i64)
            .or(created.and_then(unix_ms_to_i64));
        let title_out = format!("Samsung Note: {}", title_str);
        let detail = format!("Samsung Notes title='{}'", title_str);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Samsung Notes",
            title_out,
            detail,
            path,
            ts,
            ForensicValue::Medium,
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
            CREATE TABLE note (
                _id INTEGER PRIMARY KEY,
                title TEXT,
                content_text TEXT,
                created_time INTEGER,
                modified_time INTEGER,
                is_trashed INTEGER
            );
            INSERT INTO note VALUES(1,'Shopping','Milk, bread, eggs',1609459200000,1609459300000,0);
            INSERT INTO note VALUES(2,'Passwords','wifi: secret123',1609459400000,1609459500000,0);
            INSERT INTO note VALUES(3,'Deleted Note','Evidence gone',1609459600000,1609459700000,1);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_notes() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Samsung Notes"));
    }

    #[test]
    fn trashed_note_is_suspicious() {
        let db = make_db();
        let r = parse(db.path());
        let trashed = r
            .iter()
            .find(|a| a.detail.contains("trashed=true"))
            .unwrap();
        assert!(trashed.is_suspicious);
    }

    #[test]
    fn body_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("body='Milk, bread, eggs'")));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}

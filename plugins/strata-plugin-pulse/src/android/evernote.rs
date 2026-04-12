//! Evernote — note content and metadata extraction.
//!
//! Source: /data/data/com.evernote/databases/evernote.db

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.evernote/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "notes") {
        return Vec::new();
    }
    read_notes(&conn, path)
}

fn read_notes(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT title, created, updated, content_preview \
               FROM notes \
               ORDER BY updated DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (title, created, updated, content_preview) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let preview = content_preview.unwrap_or_default();
        let ts = updated.and_then(unix_ms_to_i64).or(created.and_then(unix_ms_to_i64));
        let snippet: String = preview.chars().take(120).collect();
        let display = format!("Evernote Note: {}", title_str);
        let detail = format!(
            "Evernote note title='{}' preview='{}'",
            title_str, snippet
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Evernote Note",
            display,
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
            CREATE TABLE notes (
                _id INTEGER PRIMARY KEY,
                title TEXT,
                created INTEGER,
                updated INTEGER,
                content_preview TEXT
            );
            INSERT INTO notes VALUES(1,'Work Notes',1609459200000,1609459300000,'Quarterly review agenda items');
            INSERT INTO notes VALUES(2,'Travel Plans',1609459400000,1609459500000,'Flight to SFO on Jan 15');
            INSERT INTO notes VALUES(3,'Recipe',1609459600000,1609459700000,'Grandma chocolate cake recipe');
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
        assert!(r.iter().all(|a| a.subcategory == "Evernote Note"));
    }

    #[test]
    fn title_and_preview_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("title='Work Notes'")));
        assert!(r.iter().any(|a| a.detail.contains("preview='Quarterly review agenda items'")));
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

//! Google Keep — Android notes and list extraction.
//!
//! ALEAPP reference: `scripts/artifacts/keepNotes.py`. Source path:
//! `/data/data/com.google.android.keep/databases/keep.db`.
//!
//! Key table: `tree_entity` (modern) or `text_search_note_content_content` (older).

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.google.android.keep/databases/keep.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "tree_entity") {
        out.extend(read_tree_entity(&conn, path));
    } else if table_exists(&conn, "text_search_note_content_content") {
        out.extend(read_search_content(&conn, path));
    }
    out
}

fn read_tree_entity(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT time_created, time_last_updated, title, text, \
               last_modifier_email \
               FROM tree_entity \
               WHERE text IS NOT NULL AND text != '' \
               ORDER BY time_last_updated DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (created, updated, title, text, modifier) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let body = text.unwrap_or_default();
        let ts = updated.and_then(unix_ms_to_i64).or(created.and_then(unix_ms_to_i64));
        let preview: String = body.chars().take(120).collect();
        let display = if title_str == "(untitled)" { &preview } else { &title_str };
        let title_out = format!("Keep note: {}", display);
        let mut detail = format!(
            "Google Keep note title='{}' body='{}'",
            title_str, body
        );
        if let Some(m) = modifier.filter(|m| !m.is_empty()) {
            detail.push_str(&format!(" modifier='{}'", m));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Google Keep Note",
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

fn read_search_content(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT c0title, c1text \
               FROM text_search_note_content_content \
               WHERE c1text IS NOT NULL AND c1text != '' \
               LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (title, text) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let body = text.unwrap_or_default();
        let preview: String = body.chars().take(120).collect();
        let display = if title_str == "(untitled)" { &preview } else { &title_str };
        let title_out = format!("Keep note: {}", display);
        let detail = format!(
            "Google Keep note title='{}' body='{}'",
            title_str, body
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Google Keep Note",
            title_out,
            detail,
            path,
            None,
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
            CREATE TABLE tree_entity (
                _id INTEGER PRIMARY KEY,
                time_created INTEGER,
                time_last_updated INTEGER,
                title TEXT,
                text TEXT,
                last_modifier_email TEXT
            );
            INSERT INTO tree_entity VALUES(1,1609459200000,1609459300000,'Shopping List','Milk, eggs, bread','user@gmail.com');
            INSERT INTO tree_entity VALUES(2,1609459400000,1609459500000,'Meeting Notes','Discuss Q1 budget with team',NULL);
            INSERT INTO tree_entity VALUES(3,1609459600000,1609459700000,NULL,'Quick thought about project',NULL);
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
        assert!(r.iter().all(|a| a.subcategory == "Google Keep Note"));
    }

    #[test]
    fn title_in_display() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Shopping List")));
    }

    #[test]
    fn modifier_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let note = r.iter().find(|a| a.detail.contains("Shopping List")).unwrap();
        assert!(note.detail.contains("modifier='user@gmail.com'"));
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

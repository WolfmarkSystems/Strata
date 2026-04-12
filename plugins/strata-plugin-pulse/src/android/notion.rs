//! Notion — page and workspace content extraction.
//!
//! Source: /data/data/com.notion.id/databases/notion.db

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.notion.id/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "notion") {
        return Vec::new();
    }
    read_pages(&conn, path)
}

fn read_pages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT title, created_at, type \
               FROM notion \
               ORDER BY created_at DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (title, created_at, page_type) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let page_type = page_type.unwrap_or_else(|| "page".to_string());
        let ts = created_at.and_then(unix_ms_to_i64);
        let display = format!("Notion Page: {}", title_str);
        let detail = format!(
            "Notion page title='{}' type='{}'",
            title_str, page_type
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Notion Page",
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
            CREATE TABLE notion (
                _id INTEGER PRIMARY KEY,
                title TEXT,
                created_at INTEGER,
                type TEXT
            );
            INSERT INTO notion VALUES(1,'Project Plan',1609459200000,'page');
            INSERT INTO notion VALUES(2,'Meeting Notes',1609459300000,'page');
            INSERT INTO notion VALUES(3,'Database View',1609459400000,'database');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_pages() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Notion Page"));
    }

    #[test]
    fn title_and_type_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("title='Project Plan'")));
        assert!(r.iter().any(|a| a.detail.contains("type='database'")));
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

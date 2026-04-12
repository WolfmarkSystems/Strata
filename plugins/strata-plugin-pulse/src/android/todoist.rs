//! Todoist — task and project extraction.
//!
//! Source: /data/data/com.todoist/databases/todoist.db

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.todoist/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "items") {
        return Vec::new();
    }
    read_items(&conn, path)
}

fn read_items(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT content, due_date, project_id, priority \
               FROM items \
               ORDER BY due_date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (content, due_date, project_id, priority) in rows.flatten() {
        let content_str = content.unwrap_or_else(|| "(empty)".to_string());
        let project_id = project_id.unwrap_or(0);
        let priority = priority.unwrap_or(1);
        let ts = due_date.and_then(unix_ms_to_i64);
        let preview: String = content_str.chars().take(80).collect();
        let display = format!("Todoist Task: {}", preview);
        let detail = format!(
            "Todoist task content='{}' project_id={} priority={}",
            content_str, project_id, priority
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Todoist Task",
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
            CREATE TABLE items (
                _id INTEGER PRIMARY KEY,
                content TEXT,
                due_date INTEGER,
                project_id INTEGER,
                priority INTEGER
            );
            INSERT INTO items VALUES(1,'Buy groceries',1609459200000,100,1);
            INSERT INTO items VALUES(2,'Submit report',1609459300000,200,4);
            INSERT INTO items VALUES(3,'Call dentist',1609459400000,100,2);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_tasks() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Todoist Task"));
    }

    #[test]
    fn content_and_priority_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("content='Submit report'")));
        assert!(r.iter().any(|a| a.detail.contains("priority=4")));
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

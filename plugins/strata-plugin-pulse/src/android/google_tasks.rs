//! Google Tasks — task extraction.
//!
//! Source: /data/data/com.google.android.apps.tasks/databases/tasks.db

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.google.android.apps.tasks/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "tasks") {
        return Vec::new();
    }
    read_tasks(&conn, path)
}

fn read_tasks(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT title, due_date, completed \
               FROM tasks \
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (title, due_date, completed) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let is_completed = completed.unwrap_or(0) != 0;
        let ts = due_date.and_then(unix_ms_to_i64);
        let display = format!("Google Tasks: {}", title_str);
        let detail = format!(
            "Google Tasks task title='{}' completed={}",
            title_str, is_completed
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Google Tasks",
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
            CREATE TABLE tasks (
                _id INTEGER PRIMARY KEY,
                title TEXT,
                due_date INTEGER,
                completed INTEGER
            );
            INSERT INTO tasks VALUES(1,'File taxes',1609459200000,0);
            INSERT INTO tasks VALUES(2,'Oil change',1609459300000,1);
            INSERT INTO tasks VALUES(3,'Weekly review',1609459400000,0);
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
        assert!(r.iter().all(|a| a.subcategory == "Google Tasks"));
    }

    #[test]
    fn completed_flag_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(
            |a| a.detail.contains("title='Oil change'") && a.detail.contains("completed=true")
        ));
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

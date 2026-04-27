//! OneNote — Microsoft OneNote page extraction.
//!
//! Source: /data/data/com.microsoft.office.onenote/databases/onenote.db
//!
//! Schema note: OneNote stores pages in either a `notes` or `pages` table
//! depending on app version.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.microsoft.office.onenote/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if table_exists(&conn, "notes") {
        read_pages(&conn, path, "notes")
    } else if table_exists(&conn, "pages") {
        read_pages(&conn, path, "pages")
    } else {
        Vec::new()
    }
}

fn read_pages(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT title, modified \
         FROM \"{}\" \
         ORDER BY modified DESC LIMIT 5000",
        table.replace('"', "\"\"")
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
    for (title, modified) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let ts = modified.and_then(unix_ms_to_i64);
        let display = format!("OneNote Page: {}", title_str);
        let detail = format!("OneNote page title='{}'", title_str);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "OneNote Page",
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
                modified INTEGER
            );
            INSERT INTO notes VALUES(1,'CS 101 Lecture',1609459200000);
            INSERT INTO notes VALUES(2,'Team Standup',1609459300000);
            INSERT INTO notes VALUES(3,'Personal Journal',1609459400000);
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
        assert!(r.iter().all(|a| a.subcategory == "OneNote Page"));
    }

    #[test]
    fn title_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("title='CS 101 Lecture'")));
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

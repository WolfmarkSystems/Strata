//! Costco — Android app search history.
//!
//! Source path: `/data/data/com.costco.app.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. The Costco app stores recent
//! product searches in a `search_history` table with `query` and
//! `timestamp` columns.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.costco.app.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "search_history") {
        out.extend(read_searches(&conn, path));
    }
    out
}

fn read_searches(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT query, timestamp FROM search_history \
               ORDER BY timestamp DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
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
    for (query, ts_ms) in rows.flatten() {
        let q = query.unwrap_or_default();
        if q.is_empty() {
            continue;
        }
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Costco search: {}", q);
        let detail = format!("Costco search query='{}'", q);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Costco Activity",
            title,
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
            CREATE TABLE search_history (
                id INTEGER PRIMARY KEY,
                query TEXT,
                timestamp INTEGER
            );
            INSERT INTO search_history VALUES(1,'kirkland vodka',1609459200000);
            INSERT INTO search_history VALUES(2,'rotisserie chicken',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_search_entries() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Costco Activity"));
    }

    #[test]
    fn query_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("query='kirkland vodka'")));
        assert!(r.iter().any(|a| a.title.contains("rotisserie chicken")));
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

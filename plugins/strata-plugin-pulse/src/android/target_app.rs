//! Target — Android app search history and order activity.
//!
//! Source path: `/data/data/com.target.ui/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. The Target app stores recent
//! searches in `search_history` and order records in `orders`. Column
//! names are probed defensively.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.target.ui/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "search_history") {
        out.extend(read_searches(&conn, path));
    }
    if table_exists(&conn, "orders") {
        out.extend(read_orders(&conn, path));
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
        let title = format!("Target search: {}", q);
        let detail = format!("Target search query='{}'", q);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Target Activity",
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

fn read_orders(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT order_id, status, total, timestamp \
               FROM orders ORDER BY timestamp DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (order_id, status, total, ts_ms) in rows.flatten() {
        let order_id = order_id.unwrap_or_else(|| "(unknown)".to_string());
        let status = status.unwrap_or_else(|| "unknown".to_string());
        let total = total.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Target order: {} ({})", order_id, status);
        let detail = format!(
            "Target order order_id='{}' status='{}' total='{}'",
            order_id, status, total
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Target Activity",
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
            INSERT INTO search_history VALUES(1,'diapers',1609459200000);
            INSERT INTO search_history VALUES(2,'trail camera',1609459300000);
            CREATE TABLE orders (
                order_id TEXT,
                status TEXT,
                total TEXT,
                timestamp INTEGER
            );
            INSERT INTO orders VALUES('TGT-98765','shipped','$32.50',1609459400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_searches_and_orders() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Target Activity"));
    }

    #[test]
    fn search_query_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("trail camera")));
        assert!(r.iter().any(|a| a.detail.contains("query='diapers'")));
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

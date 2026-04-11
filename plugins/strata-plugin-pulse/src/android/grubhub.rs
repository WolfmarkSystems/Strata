//! Grubhub — Android food delivery order extraction.
//!
//! Source path: `/data/data/com.grubhub.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Grubhub uses Room databases with
//! tables like `orders`, `restaurants`, `order_items`. Column names vary
//! across versions.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.grubhub.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    for table in &["orders", "order_history"] {
        if table_exists(&conn, table) {
            return read_orders(&conn, path, table);
        }
    }
    Vec::new()
}

fn read_orders(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT order_id, restaurant_name, placed_at, total, \
         delivery_address, delivery_instructions, status \
         FROM \"{table}\" ORDER BY placed_at DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (order_id, restaurant, placed_ms, total, address, instructions, status) in rows.flatten() {
        let order_id = order_id.unwrap_or_else(|| "(unknown)".to_string());
        let restaurant = restaurant.unwrap_or_else(|| "(unknown)".to_string());
        let total = total.unwrap_or_default();
        let address = address.unwrap_or_default();
        let instructions = instructions.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = placed_ms.and_then(unix_ms_to_i64);
        let title = format!("Grubhub: {} ({})", restaurant, total);
        let mut detail = format!(
            "Grubhub order id='{}' restaurant='{}' total='{}' status='{}'",
            order_id, restaurant, total, status
        );
        if !address.is_empty() {
            detail.push_str(&format!(" delivery_address='{}'", address));
        }
        if !instructions.is_empty() {
            detail.push_str(&format!(" instructions='{}'", instructions));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Grubhub Order",
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
            CREATE TABLE orders (
                order_id TEXT,
                restaurant_name TEXT,
                placed_at INTEGER,
                total TEXT,
                delivery_address TEXT,
                delivery_instructions TEXT,
                status TEXT
            );
            INSERT INTO orders VALUES('gh-001','Sushi Place',1609459200000,'$35.00','789 Oak St','Leave at door','delivered');
            INSERT INTO orders VALUES('gh-002','Taco Truck',1609545600000,'$12.50','789 Oak St','',NULL);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_orders() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Grubhub Order"));
    }

    #[test]
    fn delivery_instructions_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("instructions='Leave at door'")));
    }

    #[test]
    fn restaurant_and_total_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Sushi Place") && a.title.contains("$35.00")));
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

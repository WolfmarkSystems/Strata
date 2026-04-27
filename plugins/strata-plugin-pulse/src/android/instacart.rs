//! Instacart — Android grocery delivery order extraction.
//!
//! Source path: `/data/data/com.instacart.client/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Instacart uses Room databases
//! with tables like `orders`, `order_items`, `retailers`. Column names
//! vary across versions.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.instacart.client/databases/"];

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
        "SELECT order_id, retailer_name, placed_at, total, \
         delivery_address, shopper_name, status, item_count \
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
            row.get::<_, Option<i64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (order_id, retailer, placed_ms, total, address, shopper, status, item_count) in
        rows.flatten()
    {
        let order_id = order_id.unwrap_or_else(|| "(unknown)".to_string());
        let retailer = retailer.unwrap_or_else(|| "(unknown)".to_string());
        let total = total.unwrap_or_default();
        let address = address.unwrap_or_default();
        let shopper = shopper.unwrap_or_default();
        let status = status.unwrap_or_default();
        let item_count = item_count.unwrap_or(0);
        let ts = placed_ms.and_then(unix_ms_to_i64);
        let title = format!("Instacart: {} ({}, {} items)", retailer, total, item_count);
        let mut detail = format!(
            "Instacart order id='{}' retailer='{}' total='{}' item_count={} status='{}'",
            order_id, retailer, total, item_count, status
        );
        if !address.is_empty() {
            detail.push_str(&format!(" delivery_address='{}'", address));
        }
        if !shopper.is_empty() {
            detail.push_str(&format!(" shopper='{}'", shopper));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Instacart Order",
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
                retailer_name TEXT,
                placed_at INTEGER,
                total TEXT,
                delivery_address TEXT,
                shopper_name TEXT,
                status TEXT,
                item_count INTEGER
            );
            INSERT INTO orders VALUES('ic-001','Whole Foods',1609459200000,'$120.50','123 Main St','Sarah L','delivered',25);
            INSERT INTO orders VALUES('ic-002','Safeway',1609545600000,'$85.00','456 Elm St','Tom K','delivered',18);
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
        assert!(r.iter().all(|a| a.subcategory == "Instacart Order"));
    }

    #[test]
    fn item_count_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("25 items")));
    }

    #[test]
    fn shopper_name_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("shopper='Sarah L'")));
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

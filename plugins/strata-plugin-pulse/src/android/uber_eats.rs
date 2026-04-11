//! Uber Eats — Android food delivery order extraction.
//!
//! Source path: `/data/data/com.ubercab.eats/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Uber Eats stores orders in
//! `orders` or `order_history` with restaurant, items, and delivery
//! address fields. Schema varies by app version.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.ubercab.eats/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    for table in &["orders", "order_history", "order"] {
        if table_exists(&conn, table) {
            return read_orders(&conn, path, table);
        }
    }
    Vec::new()
}

fn read_orders(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT order_uuid, restaurant_name, restaurant_uuid, \
         placed_time, total, delivery_address, delivery_lat, delivery_lon, \
         status FROM \"{table}\" \
         ORDER BY placed_time DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (uuid, restaurant, rest_uuid, placed_ms, total, address, lat, lon, status) in rows.flatten() {
        let uuid = uuid.unwrap_or_else(|| "(unknown)".to_string());
        let restaurant = restaurant.unwrap_or_else(|| "(unknown)".to_string());
        let rest_uuid = rest_uuid.unwrap_or_default();
        let total = total.unwrap_or_default();
        let address = address.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = placed_ms.and_then(unix_ms_to_i64);
        let title = format!("UberEats: {} ({})", restaurant, total);
        let mut detail = format!(
            "Uber Eats order uuid='{}' restaurant='{}' restaurant_uuid='{}' total='{}' status='{}'",
            uuid, restaurant, rest_uuid, total, status
        );
        if !address.is_empty() {
            detail.push_str(&format!(" delivery_address='{}'", address));
        }
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" delivery_lat={:.6} delivery_lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Uber Eats Order",
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
                order_uuid TEXT,
                restaurant_name TEXT,
                restaurant_uuid TEXT,
                placed_time INTEGER,
                total TEXT,
                delivery_address TEXT,
                delivery_lat REAL,
                delivery_lon REAL,
                status TEXT
            );
            INSERT INTO orders VALUES('o-001','Thai Place','r-abc',1609459200000,'$25.50','123 Main St',37.7749,-122.4194,'delivered');
            INSERT INTO orders VALUES('o-002','Pizza Shop','r-def',1609545600000,'$18.75','456 Elm St',37.7700,-122.4000,'delivered');
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
        assert!(r.iter().all(|a| a.subcategory == "Uber Eats Order"));
    }

    #[test]
    fn delivery_address_and_gps() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("delivery_address='123 Main St'")));
        assert!(r.iter().any(|a| a.detail.contains("delivery_lat=37.774900")));
    }

    #[test]
    fn restaurant_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Thai Place")));
        assert!(r.iter().any(|a| a.title.contains("Pizza Shop")));
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

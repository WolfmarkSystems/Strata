//! DoorDash — Android food delivery order extraction.
//!
//! Source path: `/data/data/com.dd.doordash/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. DoorDash uses Room databases
//! with tables like `orders`, `order_item`, `merchant`. Column names
//! vary across versions.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.dd.doordash/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["orders", "order"] {
        if table_exists(&conn, table) {
            out.extend(read_orders(&conn, path, table));
            break;
        }
    }
    for table in &["merchant", "store", "restaurant"] {
        if table_exists(&conn, table) {
            out.extend(read_merchants(&conn, path, table));
            break;
        }
    }
    out
}

fn read_orders(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT order_id, store_name, created_at, subtotal, delivery_fee, \
         tip, total, delivery_address, status \
         FROM \"{table}\" ORDER BY created_at DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (order_id, store, created_ms, subtotal, delivery_fee, tip, total, address, status) in rows.flatten() {
        let order_id = order_id.unwrap_or_else(|| "(unknown)".to_string());
        let store = store.unwrap_or_else(|| "(unknown)".to_string());
        let subtotal = subtotal.unwrap_or_default();
        let delivery_fee = delivery_fee.unwrap_or_default();
        let tip = tip.unwrap_or_default();
        let total = total.unwrap_or_default();
        let address = address.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("DoorDash: {} ({})", store, total);
        let mut detail = format!(
            "DoorDash order id='{}' store='{}' subtotal='{}' delivery_fee='{}' tip='{}' total='{}' status='{}'",
            order_id, store, subtotal, delivery_fee, tip, total, status
        );
        if !address.is_empty() {
            detail.push_str(&format!(" delivery_address='{}'", address));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "DoorDash Order",
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

fn read_merchants(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, name, address, latitude, longitude, phone_number \
         FROM \"{table}\" LIMIT 1000",
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
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, address, lat, lon, phone) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let address = address.unwrap_or_default();
        let phone = phone.unwrap_or_default();
        let title = format!("DoorDash merchant: {}", name);
        let mut detail = format!(
            "DoorDash merchant id='{}' name='{}' address='{}' phone='{}'",
            id, name, address, phone
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "DoorDash Merchant",
            title,
            detail,
            path,
            None,
            ForensicValue::Low,
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
                store_name TEXT,
                created_at INTEGER,
                subtotal TEXT,
                delivery_fee TEXT,
                tip TEXT,
                total TEXT,
                delivery_address TEXT,
                status TEXT
            );
            INSERT INTO orders VALUES('dd-001','Burger Joint',1609459200000,'$15.00','$3.99','$3.00','$21.99','123 Main St','delivered');
            CREATE TABLE merchant (
                id TEXT,
                name TEXT,
                address TEXT,
                latitude REAL,
                longitude REAL,
                phone_number TEXT
            );
            INSERT INTO merchant VALUES('m-001','Burger Joint','456 Elm St',37.7749,-122.4194,'555-0100');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_orders_and_merchants() {
        let db = make_db();
        let r = parse(db.path());
        let orders: Vec<_> = r.iter().filter(|a| a.subcategory == "DoorDash Order").collect();
        let merchants: Vec<_> = r.iter().filter(|a| a.subcategory == "DoorDash Merchant").collect();
        assert_eq!(orders.len(), 1);
        assert_eq!(merchants.len(), 1);
    }

    #[test]
    fn tip_and_total_captured() {
        let db = make_db();
        let r = parse(db.path());
        let o = r.iter().find(|a| a.subcategory == "DoorDash Order").unwrap();
        assert!(o.detail.contains("tip='$3.00'"));
        assert!(o.detail.contains("total='$21.99'"));
    }

    #[test]
    fn merchant_phone_and_gps() {
        let db = make_db();
        let r = parse(db.path());
        let m = r.iter().find(|a| a.subcategory == "DoorDash Merchant").unwrap();
        assert!(m.detail.contains("phone='555-0100'"));
        assert!(m.detail.contains("lat=37.774900"));
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

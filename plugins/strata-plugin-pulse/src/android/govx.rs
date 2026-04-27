//! GovX — military/gov verified identity discount app.
//!
//! Source path: `/data/data/com.govx.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. GovX caches user verification
//! status, order history, and identity docs. Forensic value: confirms
//! military/government affiliation and purchase history.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.govx.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "user") {
        out.extend(read_user(&conn, path));
    }
    for table in &["order", "order_history"] {
        if table_exists(&conn, table) {
            out.extend(read_orders(&conn, path, table));
            break;
        }
    }
    out
}

fn read_user(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, email, first_name, last_name, \
               verification_status, verification_type, verified_at \
               FROM user LIMIT 10";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, email, first, last, status, verification_type, verified_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let email = email.unwrap_or_default();
        let first = first.unwrap_or_default();
        let last = last.unwrap_or_default();
        let status = status.unwrap_or_default();
        let verification_type = verification_type.unwrap_or_default();
        let ts = verified_ms.and_then(unix_ms_to_i64);
        let title = format!("GovX user: {} {} ({})", first, last, verification_type);
        let detail = format!(
            "GovX user id='{}' email='{}' name='{} {}' verification_status='{}' verification_type='{}'",
            id, email, first, last, status, verification_type
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "GovX User",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

fn read_orders(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, brand_name, product_name, total, ordered_at, \
         shipping_address, status \
         FROM \"{table}\" ORDER BY ordered_at DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, brand, product, total, ts_ms, shipping, status) in rows.flatten() {
        let id = id.unwrap_or_default();
        let brand = brand.unwrap_or_default();
        let product = product.unwrap_or_default();
        let total = total.unwrap_or_default();
        let shipping = shipping.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("GovX order: {} — {}", brand, product);
        let mut detail = format!(
            "GovX order id='{}' brand='{}' product='{}' total='{}' status='{}'",
            id, brand, product, total, status
        );
        if !shipping.is_empty() {
            detail.push_str(&format!(" shipping_address='{}'", shipping));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "GovX Order",
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
            CREATE TABLE user (id TEXT, email TEXT, first_name TEXT, last_name TEXT, verification_status TEXT, verification_type TEXT, verified_at INTEGER);
            INSERT INTO user VALUES('u1','john@army.mil','John','Smith','verified','active_military',1609459200000);
            CREATE TABLE "order" (id TEXT, brand_name TEXT, product_name TEXT, total TEXT, ordered_at INTEGER, shipping_address TEXT, status TEXT);
            INSERT INTO "order" VALUES('o1','Oakley','SI M Frame 3.0','$89.99',1609459300000,'123 Main St, Fort Meade MD','delivered');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_user_and_orders() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "GovX User"));
        assert!(r.iter().any(|a| a.subcategory == "GovX Order"));
    }

    #[test]
    fn verification_type_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("verification_type='active_military'")));
    }

    #[test]
    fn shipping_address_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a
            .detail
            .contains("shipping_address='123 Main St, Fort Meade MD'")));
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

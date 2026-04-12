//! Booking.com — Android reservation history extraction.
//!
//! Source path: `/data/data/com.booking/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Booking.com uses Room databases with
//! tables like `reservations` or `bookings`. Key fields include property_name,
//! city, country, check_in, check_out, guests, total_price.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.booking/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let table = if table_exists(&conn, "reservations") {
        "reservations"
    } else if table_exists(&conn, "bookings") {
        "bookings"
    } else if table_exists(&conn, "booking") {
        "booking"
    } else {
        return Vec::new();
    };
    read_reservations(&conn, path, table)
}

fn read_reservations(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT property_name, city, country, check_in, check_out, \
         guests, total_price, currency, confirmation_number, status \
         FROM \"{t}\" ORDER BY check_in DESC LIMIT 2000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
            row.get::<_, Option<String>>(9).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (property, city, country, check_in_ms, check_out_ms, guests, price, currency, confirm, status) in
        rows.flatten()
    {
        let property = property.unwrap_or_else(|| "(unknown)".to_string());
        let city = city.unwrap_or_default();
        let country = country.unwrap_or_default();
        let guests = guests.unwrap_or(0);
        let price = price.unwrap_or_default();
        let currency = currency.unwrap_or_default();
        let confirm = confirm.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = check_in_ms.and_then(unix_ms_to_i64);
        let check_in_str = fmt_ts(check_in_ms.and_then(unix_ms_to_i64));
        let check_out_str = fmt_ts(check_out_ms.and_then(unix_ms_to_i64));
        let title = format!("Booking.com: {} ({}, {})", property, city, country);
        let detail = format!(
            "Booking.com reservation property='{}' city='{}' country='{}' \
             check_in='{}' check_out='{}' guests={} total_price='{}' currency='{}' \
             confirmation='{}' status='{}'",
            property, city, country, check_in_str, check_out_str, guests,
            price, currency, confirm, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Booking.com Reservation",
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE reservations (
                property_name TEXT,
                city TEXT,
                country TEXT,
                check_in INTEGER,
                check_out INTEGER,
                guests INTEGER,
                total_price TEXT,
                currency TEXT,
                confirmation_number TEXT,
                status TEXT
            );
            INSERT INTO reservations VALUES(
                'Hotel Le Marais','Paris','France',
                1700000000000,1700259200000,
                2,'€520.00','EUR','BK-44912','confirmed'
            );
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_one_reservation() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 1);
        assert!(r[0].subcategory == "Booking.com Reservation");
    }

    #[test]
    fn city_and_country_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r[0].detail.contains("city='Paris'"));
        assert!(r[0].detail.contains("country='France'"));
    }

    #[test]
    fn guest_count_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r[0].detail.contains("guests=2"));
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

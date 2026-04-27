//! Hotels.com — Android hotel booking history extraction.
//!
//! Source path: `/data/data/com.hcom.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Hotels.com stores booking history in
//! Room databases with tables like `bookings`. Key fields include hotel_name,
//! check_in, check_out, room_type, total_price, and confirmation_number.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.hcom.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let table = if table_exists(&conn, "bookings") {
        "bookings"
    } else if table_exists(&conn, "booking_history") {
        "booking_history"
    } else if table_exists(&conn, "reservations") {
        "reservations"
    } else {
        return Vec::new();
    };
    read_bookings(&conn, path, table)
}

fn read_bookings(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT hotel_name, check_in, check_out, room_type, \
         total_price, currency, confirmation_number, status \
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
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (hotel, check_in_ms, check_out_ms, room_type, price, currency, confirm, status) in
        rows.flatten()
    {
        let hotel = hotel.unwrap_or_else(|| "(unknown)".to_string());
        let room_type = room_type.unwrap_or_default();
        let price = price.unwrap_or_default();
        let currency = currency.unwrap_or_default();
        let confirm = confirm.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = check_in_ms.and_then(unix_ms_to_i64);
        let check_in_str = fmt_ts(check_in_ms.and_then(unix_ms_to_i64));
        let check_out_str = fmt_ts(check_out_ms.and_then(unix_ms_to_i64));
        let title = format!("Hotels.com booking: {}", hotel);
        let detail = format!(
            "Hotels.com booking hotel='{}' check_in='{}' check_out='{}' \
             room_type='{}' total_price='{}' currency='{}' confirmation='{}' status='{}'",
            hotel, check_in_str, check_out_str, room_type, price, currency, confirm, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Hotels.com Booking",
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
            CREATE TABLE bookings (
                hotel_name TEXT,
                check_in INTEGER,
                check_out INTEGER,
                room_type TEXT,
                total_price TEXT,
                currency TEXT,
                confirmation_number TEXT,
                status TEXT
            );
            INSERT INTO bookings VALUES(
                'Marriott Downtown','1700000000000','1700172800000',
                'King Suite','$310.00','USD','HTL-88821','confirmed'
            );
            INSERT INTO bookings VALUES(
                'Hilton Airport','1698000000000','1698086400000',
                'Standard Room','$199.00','USD','HTL-77420','completed'
            );
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_bookings() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Hotels.com Booking"));
    }

    #[test]
    fn confirmation_number_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("confirmation='HTL-88821'")));
    }

    #[test]
    fn room_type_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("room_type='King Suite'")));
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

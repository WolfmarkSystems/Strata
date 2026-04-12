//! VRBO — Android vacation rental reservation and saved property extraction.
//!
//! Source path: `/data/data/com.vrbo.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. VRBO (Vacation Rentals By Owner) uses
//! Room databases with tables like `reservations` and `saved_properties`.
//! Schema varies across app versions; defensive checks applied throughout.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.vrbo.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_reservations(&conn, path));
    out.extend(parse_saved_properties(&conn, path));
    out
}

fn parse_reservations(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "reservations") {
        "reservations"
    } else if table_exists(conn, "booking") {
        "booking"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT property_name, host_name, check_in, check_out, \
         location, total_price, confirmation_code, guest_count \
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
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
    for (property, host, check_in_ms, check_out_ms, location, price, confirm, guests) in
        rows.flatten()
    {
        let property = property.unwrap_or_else(|| "(unknown)".to_string());
        let host = host.unwrap_or_default();
        let location = location.unwrap_or_default();
        let price = price.unwrap_or_default();
        let confirm = confirm.unwrap_or_default();
        let guests = guests.unwrap_or(0);
        let ts = check_in_ms.and_then(unix_ms_to_i64);
        let check_in_str = fmt_ts(check_in_ms.and_then(unix_ms_to_i64));
        let check_out_str = fmt_ts(check_out_ms.and_then(unix_ms_to_i64));
        let title = format!("VRBO reservation: {}", property);
        let detail = format!(
            "VRBO reservation property='{}' host='{}' location='{}' \
             check_in='{}' check_out='{}' total_price='{}' confirmation='{}' guests={}",
            property, host, location, check_in_str, check_out_str, price, confirm, guests
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "VRBO Reservation",
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

fn parse_saved_properties(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "saved_properties") {
        "saved_properties"
    } else if table_exists(conn, "favorites") {
        "favorites"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT property_id, property_name, location, saved_at \
         FROM \"{t}\" ORDER BY saved_at DESC LIMIT 2000",
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, location, saved_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let location = location.unwrap_or_default();
        let ts = saved_ms.and_then(unix_ms_to_i64);
        let title = format!("VRBO saved: {}", name);
        let detail = format!(
            "VRBO saved_property id='{}' name='{}' location='{}' saved_at='{}'",
            id,
            name,
            location,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "VRBO Saved Property",
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
            CREATE TABLE reservations (
                property_name TEXT,
                host_name TEXT,
                check_in INTEGER,
                check_out INTEGER,
                location TEXT,
                total_price TEXT,
                confirmation_code TEXT,
                guest_count INTEGER
            );
            INSERT INTO reservations VALUES(
                'Lakefront Cabin','Bob T',
                1700000000000,1700432000000,
                'Lake Tahoe, NV','$850.00','VRB3991',3
            );
            CREATE TABLE saved_properties (
                property_id TEXT,
                property_name TEXT,
                location TEXT,
                saved_at INTEGER
            );
            INSERT INTO saved_properties VALUES('prop-42','Beach House','Malibu, CA',1699800000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_reservation() {
        let db = make_db();
        let r = parse(db.path());
        let res: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "VRBO Reservation")
            .collect();
        assert_eq!(res.len(), 1);
        assert!(res[0].detail.contains("property='Lakefront Cabin'"));
        assert!(res[0].detail.contains("confirmation='VRB3991'"));
        assert!(res[0].detail.contains("guests=3"));
    }

    #[test]
    fn parses_saved_property() {
        let db = make_db();
        let r = parse(db.path());
        let saved: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "VRBO Saved Property")
            .collect();
        assert_eq!(saved.len(), 1);
        assert!(saved[0].detail.contains("name='Beach House'"));
    }

    #[test]
    fn forensic_value_is_critical_for_reservation() {
        let db = make_db();
        let r = parse(db.path());
        let res: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "VRBO Reservation")
            .collect();
        assert!(res.iter().all(|a| a.forensic_value == ForensicValue::Critical));
    }

    #[test]
    fn missing_tables_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}

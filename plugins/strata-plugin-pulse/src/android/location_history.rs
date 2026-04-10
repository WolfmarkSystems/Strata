//! Location history — fused-location provider cache.
//!
//! ALEAPP reference: `scripts/artifacts/locationHistory.py`,
//! `scripts/artifacts/locationCellWifiInfo.py`. Source paths:
//!
//! - `/data/data/com.google.android.location/files/cache.cell`
//! - `/data/data/com.google.android.gms/databases/location_history.db`
//! - `/data/data/com.google.android.gms/databases/herrevad-snets-database`
//!
//! Pulse parses the SQLite form. Schema varies, but the common columns
//! are `latitude`, `longitude`, `accuracy`, `timestamp` (ms).

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, unix_ms_to_i64};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "location_history.db",
    "herrevad",
    "fused_location",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    // Find any table containing all of latitude/longitude.
    let candidate = find_geo_table(&conn);
    let Some(table) = candidate else {
        return Vec::new();
    };
    read(&conn, path, &table)
}

fn find_geo_table(conn: &Connection) -> Option<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .ok()?;
    let names: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .ok()?
        .flatten()
        .collect();
    names.into_iter().find(|table| {
        column_exists(conn, table, "latitude") && column_exists(conn, table, "longitude")
    })
}

fn read(conn: &Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let has_acc = column_exists(conn, table, "accuracy");
    let has_ts = column_exists(conn, table, "timestamp");
    let sql = format!(
        "SELECT latitude, longitude, {}, {} FROM \"{}\" LIMIT 20000",
        if has_acc { "accuracy" } else { "0" },
        if has_ts { "timestamp" } else { "0" },
        table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<f64>>(0).unwrap_or(None),
            row.get::<_, Option<f64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (lat, lon, acc, ts_ms) in rows.flatten() {
        let la = lat.unwrap_or(0.0);
        let lo = lon.unwrap_or(0.0);
        if la == 0.0 && lo == 0.0 {
            continue;
        }
        let ts = ts_ms.and_then(unix_ms_to_i64);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Android Location History",
            format!("Location: ({:.6}, {:.6})", la, lo),
            format!(
                "Recorded location lat={:.6} lon={:.6} accuracy_m={:.1}",
                la,
                lo,
                acc.unwrap_or(0.0)
            ),
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
            CREATE TABLE LocationHistory (
                id INTEGER PRIMARY KEY,
                latitude REAL,
                longitude REAL,
                accuracy REAL,
                timestamp INTEGER
            );
            INSERT INTO LocationHistory VALUES (1,37.4219,-122.0840,12.5,1609459200000);
            INSERT INTO LocationHistory VALUES (2,40.7128,-74.0060,8.0,1609459300000);
            INSERT INTO LocationHistory VALUES (3,0,0,0,0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_locations_drops_zero() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn coordinates_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|x| x.title.contains("37.421900")));
        assert!(r.iter().any(|x| x.title.contains("40.712800")));
    }

    #[test]
    fn forensic_value_is_high() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().all(|x| x.forensic_value == ForensicValue::High));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE foo(x INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}

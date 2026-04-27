//! Citymapper — transit navigation history.
//!
//! ALEAPP reference: `scripts/artifacts/citymapper.py`. Source path:
//! `/data/data/com.citymapper.app.release/databases/citymapper.db`.
//!
//! Key tables: `locationhistoryentry`, `savedtripentry`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.citymapper.app.release/databases/citymapper.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "locationhistoryentry") {
        out.extend(read_history(&conn, path));
    }
    if table_exists(&conn, "savedtripentry") {
        out.extend(read_saved_trips(&conn, path));
    }
    out
}

fn read_history(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, address, date, lat, lng, name, role \
               FROM locationhistoryentry \
               ORDER BY date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, address, date_ms, lat, lng, name, role) in rows.flatten() {
        let id = id.unwrap_or(0);
        let address = address.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let role = role.unwrap_or_default();
        let ts = date_ms.and_then(unix_ms_to_i64);
        let title = format!("Citymapper location: {}", name);
        let mut detail = format!(
            "Citymapper location id={} name='{}' address='{}'",
            id, name, address
        );
        if !role.is_empty() {
            detail.push_str(&format!(" role='{}'", role));
        }
        if let (Some(la), Some(lo)) = (lat, lng) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Citymapper Location",
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

fn read_saved_trips(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, commuteType, created, homeLat, homeLng, workLat, workLng, regionCode \
               FROM savedtripentry LIMIT 1000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, commute, created_ms, h_lat, h_lng, w_lat, w_lng, region) in rows.flatten() {
        let id = id.unwrap_or(0);
        let commute = commute.unwrap_or_default();
        let region = region.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("Citymapper saved trip #{} ({})", id, commute);
        let mut detail = format!(
            "Citymapper saved trip id={} commute_type='{}' region='{}'",
            id, commute, region
        );
        if let (Some(la), Some(lo)) = (h_lat, h_lng) {
            detail.push_str(&format!(" home_lat={:.6} home_lon={:.6}", la, lo));
        }
        if let (Some(la), Some(lo)) = (w_lat, w_lng) {
            detail.push_str(&format!(" work_lat={:.6} work_lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Citymapper Trip",
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
            CREATE TABLE locationhistoryentry (
                id INTEGER PRIMARY KEY,
                address TEXT,
                date INTEGER,
                lat REAL,
                lng REAL,
                name TEXT,
                role TEXT
            );
            INSERT INTO locationhistoryentry VALUES(1,'123 Main St',1609459200000,40.7128,-74.0060,'Office','work');
            INSERT INTO locationhistoryentry VALUES(2,'456 Park Ave',1609459300000,40.7589,-73.9851,'Coffee','search');
            CREATE TABLE savedtripentry (
                id INTEGER PRIMARY KEY,
                commuteType TEXT,
                created INTEGER,
                homeLat REAL,
                homeLng REAL,
                workLat REAL,
                workLng REAL,
                tripData TEXT,
                regionCode TEXT
            );
            INSERT INTO savedtripentry VALUES(1,'DAILY',1609459200000,40.7500,-73.9857,40.7128,-74.0060,'{}','NYC');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_history_and_trips() {
        let db = make_db();
        let r = parse(db.path());
        let hist: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Citymapper Location")
            .collect();
        let trips: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Citymapper Trip")
            .collect();
        assert_eq!(hist.len(), 2);
        assert_eq!(trips.len(), 1);
    }

    #[test]
    fn home_work_coords_in_saved_trip() {
        let db = make_db();
        let r = parse(db.path());
        let t = r
            .iter()
            .find(|a| a.subcategory == "Citymapper Trip")
            .unwrap();
        assert!(t.detail.contains("home_lat=40.750000"));
        assert!(t.detail.contains("work_lat=40.712800"));
        assert!(t.detail.contains("region='NYC'"));
    }

    #[test]
    fn location_role_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("role='work'")));
        assert!(r.iter().any(|a| a.detail.contains("role='search'")));
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

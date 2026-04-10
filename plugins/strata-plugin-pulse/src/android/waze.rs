//! Waze — Android navigation search and location history.
//!
//! ALEAPP reference: `scripts/artifacts/waze.py`. Source path:
//! `/data/data/com.waze/databases/user.db`.
//!
//! Key tables: `RECENTS` joined with `PLACES`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.waze/databases/user.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "RECENTS") && table_exists(&conn, "PLACES") {
        out.extend(read_recents(&conn, path));
    } else if table_exists(&conn, "RECENTS") {
        out.extend(read_recents_only(&conn, path));
    }
    if table_exists(&conn, "PLACES") {
        out.extend(read_places(&conn, path));
    }
    out
}

fn read_recents(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT R.access_time, R.name, P.name, \
               P.latitude, P.longitude, P.created_time \
               FROM RECENTS R \
               JOIN PLACES P ON R.place_id = P.id \
               ORDER BY R.access_time DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (access, name, address, lat_raw, lon_raw, _created) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let address = address.unwrap_or_default();
        // Waze stores coordinates as int * 1_000_000
        let lat = lat_raw.map(|l| l as f64 * 0.000001);
        let lon = lon_raw.map(|l| l as f64 * 0.000001);
        let ts = access; // Unix epoch seconds
        let title = format!("Waze search: {}", name);
        let mut detail = format!("Waze recent search name='{}' address='{}'", name, address);
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Waze Search",
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

fn read_recents_only(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT access_time, name FROM RECENTS ORDER BY access_time DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (access, name) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let title = format!("Waze search: {}", name);
        let detail = format!("Waze recent search name='{}'", name);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Waze Search",
            title,
            detail,
            path,
            access,
            ForensicValue::High,
            false,
        ));
    }
    out
}

fn read_places(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT name, latitude, longitude, created_time \
               FROM PLACES ORDER BY created_time DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, lat_raw, lon_raw, created) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let lat = lat_raw.map(|l| l as f64 * 0.000001);
        let lon = lon_raw.map(|l| l as f64 * 0.000001);
        let title = format!("Waze place: {}", name);
        let mut detail = format!("Waze saved place name='{}'", name);
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Waze Place",
            title,
            detail,
            path,
            created,
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
            CREATE TABLE PLACES (
                id INTEGER PRIMARY KEY,
                name TEXT,
                latitude INTEGER,
                longitude INTEGER,
                created_time INTEGER
            );
            INSERT INTO PLACES VALUES(1,'123 Main St, Springfield',39876543,-89654321,1609459200);
            INSERT INTO PLACES VALUES(2,'456 Oak Ave, Shelbyville',39123456,-89123456,1609459300);
            CREATE TABLE RECENTS (
                place_id INTEGER,
                name TEXT,
                access_time INTEGER
            );
            INSERT INTO RECENTS VALUES(1,'Home',1609459400);
            INSERT INTO RECENTS VALUES(2,'Work',1609459500);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_recents_and_places() {
        let db = make_db();
        let r = parse(db.path());
        let searches: Vec<_> = r.iter().filter(|a| a.subcategory == "Waze Search").collect();
        let places: Vec<_> = r.iter().filter(|a| a.subcategory == "Waze Place").collect();
        assert_eq!(searches.len(), 2);
        assert_eq!(places.len(), 2);
    }

    #[test]
    fn coordinates_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let home = r.iter().find(|a| a.title.contains("Home")).unwrap();
        assert!(home.detail.contains("lat=39.876543"));
        assert!(home.detail.contains("lon=-89.654321"));
    }

    #[test]
    fn category_is_location() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().all(|a| a.category == ArtifactCategory::UserActivity));
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

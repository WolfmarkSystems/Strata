//! Google Maps — search history + My Places.
//!
//! ALEAPP reference: `scripts/artifacts/googleMaps.py` and
//! `scripts/artifacts/googleMapsLocationHistory.py`. Source paths:
//!
//! - `/data/data/com.google.android.apps.maps/databases/gmm_storage.db`
//! - `/data/data/com.google.android.apps.maps/databases/gmm_myplaces.db`
//! - `/data/data/com.google.android.apps.maps/databases/search_history.db`
//!
//! Pulse targets the two most common schemas:
//!
//! 1. A `search_history` table with `query`, `timestamp` (ms).
//! 2. A `places` table with `name`, `latitude`, `longitude`,
//!    `last_accessed_ms`.

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["gmm_storage.db", "gmm_myplaces.db", "search_history.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "search_history") {
        read_search(&conn, path, &mut out);
    }
    if table_exists(&conn, "places") {
        read_places(&conn, path, &mut out);
    }
    out
}

fn read_search(conn: &Connection, path: &Path, out: &mut Vec<ArtifactRecord>) {
    if !column_exists(conn, "search_history", "query") {
        return;
    }
    let has_ts = column_exists(conn, "search_history", "timestamp");
    let sql = if has_ts {
        "SELECT query, timestamp FROM search_history ORDER BY timestamp DESC LIMIT 10000"
    } else {
        "SELECT query, 0 FROM search_history LIMIT 10000"
    };
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return,
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return;
    };
    for (query, ts_ms) in rows.flatten() {
        let q = query.unwrap_or_default();
        if q.is_empty() {
            continue;
        }
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Android Google Maps Search",
            format!("Map Search: {}", q),
            format!("Google Maps search query='{}'", q),
            path,
            ts_ms.and_then(unix_ms_to_i64),
            ForensicValue::Medium,
            false,
        ));
    }
}

fn read_places(conn: &Connection, path: &Path, out: &mut Vec<ArtifactRecord>) {
    let has_name = column_exists(conn, "places", "name");
    let has_lat = column_exists(conn, "places", "latitude");
    let has_lon = column_exists(conn, "places", "longitude");
    let has_ts = column_exists(conn, "places", "last_accessed_ms");
    if !(has_name && has_lat && has_lon) {
        return;
    }
    let sql = format!(
        "SELECT name, latitude, longitude, {} FROM places LIMIT 10000",
        if has_ts { "last_accessed_ms" } else { "0" }
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return,
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<f64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return;
    };
    for (name, lat, lon, ts_ms) in rows.flatten() {
        let n = name.unwrap_or_else(|| "(unnamed place)".to_string());
        let la = lat.unwrap_or(0.0);
        let lo = lon.unwrap_or(0.0);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Android Google Maps Place",
            format!("Place: {}", n),
            format!("Google Maps saved place '{}' at ({:.6},{:.6})", n, la, lo),
            path,
            ts_ms.and_then(unix_ms_to_i64),
            ForensicValue::Medium,
            false,
        ));
    }
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
            CREATE TABLE search_history (id INTEGER PRIMARY KEY, query TEXT, timestamp INTEGER);
            INSERT INTO search_history VALUES (1,'coffee near me',1609459200000);
            INSERT INTO search_history VALUES (2,'gun store',1609459300000);
            CREATE TABLE places (id INTEGER PRIMARY KEY, name TEXT, latitude REAL, longitude REAL, last_accessed_ms INTEGER);
            INSERT INTO places VALUES (1,'Home',37.4219,-122.0840,1609459400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn reads_searches_and_places() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn search_queries_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|x| x.title == "Map Search: coffee near me"));
        assert!(r.iter().any(|x| x.title == "Map Search: gun store"));
    }

    #[test]
    fn saved_places_include_coordinates() {
        let db = make_db();
        let r = parse(db.path());
        let home = r.iter().find(|x| x.title == "Place: Home").unwrap();
        assert!(home.detail.contains("37.421900"));
        assert!(home.detail.contains("-122.084000"));
    }

    #[test]
    fn missing_tables_yield_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE irrelevant(x INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}

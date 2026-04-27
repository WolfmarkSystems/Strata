//! OruxMaps — offline GPS tracking extraction.
//!
//! ALEAPP reference: `scripts/artifacts/Oruxmaps.py`. Source path:
//! `/sdcard/oruxmaps/tracklogs/oruxmapstracks.db`.
//!
//! Key tables: `pois`, `tracks`, `trackpoints`, `segments`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["oruxmaps/tracklogs/oruxmapstracks.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "pois") {
        out.extend(read_pois(&conn, path));
    }
    if table_exists(&conn, "tracks") {
        out.extend(read_tracks(&conn, path));
    }
    out
}

fn read_pois(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT poiname, poilat, poilon, poialt, poitime \
               FROM pois ORDER BY poitime DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<f64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, lat, lon, alt, time_ms) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let ts = time_ms.map(|t| t / 1000); // ms to seconds
        let title = format!("OruxMaps POI: {}", name);
        let mut detail = format!("OruxMaps POI name='{}'", name);
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let Some(a) = alt {
            detail.push_str(&format!(" altitude={:.1}m", a));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "OruxMaps POI",
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

fn read_tracks(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT _id, trackname, trackciudad \
               FROM tracks LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, city) in rows.flatten() {
        let id = id.unwrap_or(0);
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let city = city.unwrap_or_default();
        let title = format!("OruxMaps track #{}: {}", id, name);
        let mut detail = format!("OruxMaps track id={} name='{}'", id, name);
        if !city.is_empty() {
            detail.push_str(&format!(" city='{}'", city));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "OruxMaps Track",
            title,
            detail,
            path,
            None,
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
            CREATE TABLE pois (
                poiname TEXT,
                poilat REAL,
                poilon REAL,
                poialt REAL,
                poitime INTEGER
            );
            INSERT INTO pois VALUES('Summit',45.1234,-122.5678,2500.0,1609459200000);
            INSERT INTO pois VALUES('Trailhead',45.1000,-122.5500,500.0,1609459300000);
            CREATE TABLE tracks (
                _id INTEGER PRIMARY KEY,
                trackname TEXT,
                trackciudad TEXT
            );
            INSERT INTO tracks VALUES(1,'Mountain Loop','Portland');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_pois_and_tracks() {
        let db = make_db();
        let r = parse(db.path());
        let pois: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "OruxMaps POI")
            .collect();
        let tracks: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "OruxMaps Track")
            .collect();
        assert_eq!(pois.len(), 2);
        assert_eq!(tracks.len(), 1);
    }

    #[test]
    fn poi_altitude_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let summit = r.iter().find(|a| a.title.contains("Summit")).unwrap();
        assert!(summit.detail.contains("altitude=2500.0m"));
    }

    #[test]
    fn track_city_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("city='Portland'")));
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

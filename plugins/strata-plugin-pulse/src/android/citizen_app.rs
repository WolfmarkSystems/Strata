//! Citizen App — public safety incident reports with location data.
//!
//! Source path: `/data/data/com.sp0n.citizen/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Citizen uses Room databases with
//! tables like `incident`, `alert`, `event`. Location fields (latitude,
//! longitude) establish geographic awareness of crime events — forensically
//! critical for placing a subject near incident locations.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.sp0n.citizen/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["incident", "incidents", "alert", "alerts", "event"] {
        if table_exists(&conn, table) {
            out.extend(read_incidents(&conn, path, table));
            break;
        }
    }
    out
}

fn read_incidents(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, title, description, latitude, longitude, reported_at, category \
         FROM \"{table}\" ORDER BY reported_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, title, description, lat, lon, reported_ms, category) in rows.flatten() {
        let id = id.unwrap_or_default();
        let title = title.unwrap_or_else(|| "(untitled)".to_string());
        let description = description.unwrap_or_default();
        let category = category.unwrap_or_else(|| "Unknown".to_string());
        let ts = reported_ms.and_then(unix_ms_to_i64);
        let title_str = format!("Citizen incident: {} [{}]", title, category);
        let mut detail = format!(
            "Citizen incident id='{}' title='{}' category='{}' description='{}'",
            id, title, category, description
        );
        if let Some(la) = lat {
            detail.push_str(&format!(" latitude={:.6}", la));
        }
        if let Some(lo) = lon {
            detail.push_str(&format!(" longitude={:.6}", lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Citizen Incident",
            title_str,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            true,
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
            CREATE TABLE incident (
                id TEXT,
                title TEXT,
                description TEXT,
                latitude REAL,
                longitude REAL,
                reported_at INTEGER,
                category TEXT
            );
            INSERT INTO incident VALUES('inc1','Armed Robbery','Suspect fled on foot',40.712776,-74.005974,1609459200000,'Crime');
            INSERT INTO incident VALUES('inc2','Structure Fire','2-alarm fire at warehouse',34.052235,-118.243683,1609459300000,'Fire');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_incidents() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(
            r.iter()
                .filter(|a| a.subcategory == "Citizen Incident")
                .count(),
            2
        );
    }

    #[test]
    fn location_coordinates_captured() {
        let db = make_db();
        let r = parse(db.path());
        let inc = r.iter().find(|a| a.detail.contains("inc1")).unwrap();
        assert!(inc.detail.contains("latitude=40.712776"));
        assert!(inc.detail.contains("longitude=-74.005974"));
    }

    #[test]
    fn category_and_description_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("category='Crime'") && a.detail.contains("Armed Robbery")));
        assert!(r.iter().any(|a| a.detail.contains("category='Fire'")));
    }

    #[test]
    fn incidents_are_critical_forensic_value() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .all(|a| a.forensic_value == ForensicValue::Critical));
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

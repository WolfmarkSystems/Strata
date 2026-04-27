//! Garmin Connect — weight measurement extraction.
//!
//! ALEAPP reference: `scripts/artifacts/GarminWeight.py`. Source path:
//! `/data/data/com.garmin.android.apps.connectmobile/databases/cache-database`.
//!
//! Key table: `weight`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.garmin.android.apps.connectmobile/databases/cache-database"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "weight") {
        return Vec::new();
    }
    read_weight(&conn, path)
}

fn read_weight(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT samplePk, date, weight \
               FROM weight ORDER BY date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (sample_pk, date, weight) in rows.flatten() {
        let pk = sample_pk.unwrap_or(0);
        let weight_kg = weight.unwrap_or(0.0);
        let ts = date; // seconds
        let title = format!("Garmin weight: {:.2}kg", weight_kg);
        let detail = format!("Garmin weight sample_pk={} weight_kg={:.2}", pk, weight_kg);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Garmin Weight",
            title,
            detail,
            path,
            ts,
            ForensicValue::Low,
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
            CREATE TABLE weight (
                samplePk INTEGER,
                date INTEGER,
                weight REAL
            );
            INSERT INTO weight VALUES(1,1609459200,75.5);
            INSERT INTO weight VALUES(2,1609545600,75.2);
            INSERT INTO weight VALUES(3,1609632000,74.8);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_entries() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Garmin Weight"));
    }

    #[test]
    fn weight_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("75.50kg")));
    }

    #[test]
    fn sample_pk_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("sample_pk=2")));
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

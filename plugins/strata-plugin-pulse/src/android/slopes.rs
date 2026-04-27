//! Slopes — ski tracking app extraction.
//!
//! ALEAPP reference: `scripts/artifacts/slopes.py`. Source path:
//! `/data/data/com.consumedbycode.slopes/databases/slopes.db`.
//!
//! Key tables: `resort`, `action`, `lift`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.consumedbycode.slopes/databases/slopes.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "resort") {
        out.extend(read_resorts(&conn, path));
    }
    if table_exists(&conn, "action") {
        out.extend(read_actions(&conn, path));
    }
    out
}

fn read_resorts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT name, locality, admin_area, country, \
               coordinate_lat, coordinate_long, baseAltitude, summitAltitude \
               FROM resort LIMIT 1000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, locality, area, country, lat, lon, base, summit) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let locality = locality.unwrap_or_default();
        let area = area.unwrap_or_default();
        let country = country.unwrap_or_default();
        let title = format!("Slopes resort: {} ({})", name, country);
        let mut detail = format!(
            "Slopes resort name='{}' locality='{}' area='{}' country='{}'",
            name, locality, area, country
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let (Some(b), Some(s)) = (base, summit) {
            detail.push_str(&format!(" base_alt={:.0}m summit_alt={:.0}m", b, s));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Slopes Resort",
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

fn read_actions(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT start, end, duration, type, distance, \
               avg_speed, top_speed, max_alt, min_alt \
               FROM action ORDER BY start DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (start, _end, duration, kind, distance, avg_speed, top_speed, max_alt, min_alt) in
        rows.flatten()
    {
        let kind = kind.unwrap_or_else(|| "run".to_string());
        let ts = start;
        let dur = duration.unwrap_or(0);
        let title = format!("Slopes {} ({}s)", kind, dur);
        let mut detail = format!("Slopes action type='{}' duration={}s", kind, dur);
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.0}m", d));
        }
        if let Some(a) = avg_speed {
            detail.push_str(&format!(" avg_speed={:.2}", a));
        }
        if let Some(t) = top_speed {
            detail.push_str(&format!(" top_speed={:.2}", t));
        }
        if let (Some(mx), Some(mn)) = (max_alt, min_alt) {
            detail.push_str(&format!(" alt_range={:.0}-{:.0}m", mn, mx));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Slopes Action",
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
            CREATE TABLE resort (
                name TEXT,
                locality TEXT,
                admin_area TEXT,
                country TEXT,
                coordinate_lat REAL,
                coordinate_long REAL,
                baseAltitude REAL,
                summitAltitude REAL,
                distance REAL,
                veryEasyRuns INTEGER,
                easyRuns INTEGER,
                intermediateRuns INTEGER,
                expertRuns INTEGER,
                has_lift_data INTEGER
            );
            INSERT INTO resort VALUES('Whistler','Whistler','BC','Canada',50.1163,-122.9574,650.0,2284.0,1000.0,5,20,40,30,1);
            CREATE TABLE action (
                start INTEGER,
                end INTEGER,
                duration INTEGER,
                type TEXT,
                distance REAL,
                avg_speed REAL,
                top_speed REAL,
                max_alt REAL,
                min_alt REAL
            );
            INSERT INTO action VALUES(1609459200,1609459800,600,'run',3000.0,5.0,25.0,2200.0,1500.0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_resort_and_action() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Slopes Resort"));
        assert!(r.iter().any(|a| a.subcategory == "Slopes Action"));
    }

    #[test]
    fn resort_altitudes_captured() {
        let db = make_db();
        let r = parse(db.path());
        let w = r.iter().find(|a| a.detail.contains("Whistler")).unwrap();
        assert!(w.detail.contains("base_alt=650m"));
        assert!(w.detail.contains("summit_alt=2284m"));
    }

    #[test]
    fn action_speeds_and_altitudes() {
        let db = make_db();
        let r = parse(db.path());
        let a = r.iter().find(|a| a.subcategory == "Slopes Action").unwrap();
        assert!(a.detail.contains("top_speed=25.00"));
        assert!(a.detail.contains("alt_range=1500-2200m"));
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

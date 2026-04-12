//! iOS HealthKit workout routes — `healthdb_secure.sqlite` +
//! `workout_routes/` CoreLocation data.
//!
//! Workout routes embed full GPS polylines (lat/lon/alt per second)
//! recorded during outdoor workouts via Apple Watch or iPhone.
//! Proves the exact path taken at exact times. Critical for
//! alibi/location investigations.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    // Route data stored as serialized CLLocation arrays in
    // healthdb_secure.sqlite `workout_events` or as separate .gpx
    // in workout_routes/
    (util::name_is(path, &["healthdb_secure.sqlite"]))
        || (util::path_contains(path, "workout") && {
            let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            n.ends_with(".gpx") || n.ends_with(".route")
        })
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let source = path.to_string_lossy().to_string();
    let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();

    // GPX route file — presence detection
    if n.ends_with(".gpx") || n.ends_with(".route") {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size == 0 { return Vec::new(); }
        return vec![ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Workout route".to_string(), timestamp: None,
            title: "HealthKit workout GPS route".to_string(),
            detail: format!("Workout route file ({} bytes) — full GPS polyline with lat/lon/alt per second", size),
            source_path: source, forensic_value: ForensicValue::Critical,
            mitre_technique: Some("T1430".to_string()), is_suspicious: false, raw_data: None,
            confidence: 0,
        }];
    }

    // SQLite: check for workout_events with location data
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "workout_events") { return out; }
    let count = util::count_rows(&conn, "workout_events");
    if count == 0 { return out; }

    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Workout routes".to_string(), timestamp: None,
        title: "HealthKit workout route events".to_string(),
        detail: format!("{} workout_events rows — GPS route segments from Apple Watch workouts", count),
        source_path: source, forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1430".to_string()), is_suspicious: false, raw_data: None,
        confidence: 0,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::{tempdir, NamedTempFile};

    #[test]
    fn matches_gpx_under_workout_path() {
        assert!(matches(Path::new("/var/mobile/Library/Health/workout_routes/route_001.gpx")));
        assert!(matches(Path::new("/var/mobile/Library/Health/healthdb_secure.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_workout_events_count() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE workout_events (data_id INTEGER PRIMARY KEY, type INTEGER, date DOUBLE)", []).unwrap();
        c.execute("INSERT INTO workout_events (type, date) VALUES (6, 700000000.0)", []).unwrap();
        c.execute("INSERT INTO workout_events (type, date) VALUES (6, 700000001.0)", []).unwrap();
        let recs = parse(tmp.path());
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("2 workout_events"));
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }

    #[test]
    fn parses_gpx_presence() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("workout_routes");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("route_001.gpx");
        std::fs::write(&p, b"<gpx><trk><trkseg><trkpt lat='40.7' lon='-74.0'/></trkseg></trk></gpx>").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("GPS polyline"));
    }

    #[test]
    fn empty_workout_events_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE workout_events (data_id INTEGER PRIMARY KEY)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

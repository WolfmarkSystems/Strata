//! Strava iOS — `*.db` under `*strava*`.
//!
//! GPS-tracked workouts with full route geometry. Extremely high
//! location value — proves exact path taken at exact times.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "strava") && {
        let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite")
    }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .and_then(|mut s| { let r = s.query_map([], |row| row.get::<_, String>(0))?; Ok(r.flatten().collect()) })
        .unwrap_or_default();
    if tables.is_empty() { return out; }
    let mut total = 0_i64;
    for t in &tables { total += util::count_rows(&conn, t); }
    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Strava".to_string(), timestamp: None,
        title: "Strava iOS database".to_string(),
        detail: format!("{} rows across {} tables — GPS-tracked workouts with route geometry", total, tables.len()),
        source_path: source, forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1430".to_string()), is_suspicious: false, raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_strava() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/Strava/store.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_rows() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("strava");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE activities (id INTEGER PRIMARY KEY, lat REAL, lon REAL)", []).unwrap();
        c.execute("INSERT INTO activities (lat, lon) VALUES (40.7, -74.0)", []).unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }
    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("strava");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

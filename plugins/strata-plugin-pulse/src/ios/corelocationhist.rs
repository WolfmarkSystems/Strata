//! iOS CoreLocation historical visits — `cache_encryptedC.db`,
//! `visits.db` under `locationd/`.
//!
//! `ZRTVISITMO` records every place the device stopped for a
//! significant duration. Higher precision than routined/Significant
//! Locations — includes arrival/departure timestamps + confidence.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    let in_loc = util::path_contains(path, "locationd") || util::path_contains(path, "corelocation");
    in_loc && {
        let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite")
    }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();

    for (table, label) in [
        ("ZRTVISITMO", "location visits (arrival/departure with lat/lon)"),
        ("ZRTCLLOCATIONMO", "raw CLLocation samples"),
        ("ZRTLEARNEDVISITMO", "learned visit patterns"),
    ] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::UserActivity,
                subcategory: format!("CoreLocation {}", table), timestamp: None,
                title: format!("iOS CoreLocation {}", label),
                detail: format!("{} {} rows", count, table),
                source_path: source.clone(), forensic_value: ForensicValue::Critical,
                mitre_technique: Some("T1430".to_string()), is_suspicious: false, raw_data: None,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_locationd_dbs() {
        assert!(matches(Path::new("/var/root/Library/Caches/locationd/cache_encryptedC.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_visit_table() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("locationd");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("visits.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE ZRTVISITMO (Z_PK INTEGER PRIMARY KEY, ZLATITUDE REAL, ZLONGITUDE REAL)", []).unwrap();
        c.execute("INSERT INTO ZRTVISITMO (ZLATITUDE, ZLONGITUDE) VALUES (40.7, -74.0)", []).unwrap();
        let recs = parse(&p);
        assert!(recs.iter().any(|r| r.subcategory.contains("ZRTVISITMO")));
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }
    #[test]
    fn no_known_tables_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("locationd");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("visits.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}

//! iOS Find My network — AirTag location history, item beacons.
//!
//! Extends the basic `findmy.rs` (presence detection) by targeting
//! the `OwnedItems.data` and `FindMyCache.db` stores that contain
//! per-item location pings from the Find My network.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let in_findmy =
        util::path_contains(path, "searchpartyd") || util::path_contains(path, "com.apple.findmy");
    in_findmy && {
        let n = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite")
    }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .and_then(|mut s| {
            let r = s.query_map([], |row| row.get::<_, String>(0))?;
            Ok(r.flatten().collect())
        })
        .unwrap_or_default();
    if tables.is_empty() {
        return out;
    }
    let mut total = 0_i64;
    for t in &tables {
        total += util::count_rows(&conn, t);
    }
    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Find My network".to_string(),
        timestamp: None,
        title: "iOS Find My / AirTag location database".to_string(),
        detail: format!(
            "{} rows across {} tables — AirTag pings, item locations, device beacons",
            total,
            tables.len()
        ),
        source_path: source,
        forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1430".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_findmy_dbs() {
        assert!(matches(Path::new(
            "/var/mobile/Library/com.apple.icloud.searchpartyd/FindMyCache.db"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/com.apple.findmy/items.sqlite"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_rows() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("com.apple.icloud.searchpartyd");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("FindMyCache.db");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE item_locations (id INTEGER PRIMARY KEY, lat REAL, lon REAL, ts REAL)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO item_locations (lat, lon, ts) VALUES (40.7, -74.0, 700000000.0)",
            [],
        )
        .unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("com.apple.icloud.searchpartyd");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("FindMyCache.db");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

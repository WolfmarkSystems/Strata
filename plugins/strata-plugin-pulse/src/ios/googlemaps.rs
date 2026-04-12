//! Google Maps iOS — `GMMAutocomplete.sqlite`, `offlineMaps.db`.
//!
//! Google Maps stores search autocomplete history and offline map
//! metadata. Location search terms are high forensic value.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["gmmautocomplete.sqlite", "offlinemaps.db", "search_history.db"])
        && util::path_contains(path, "google")
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
        subcategory: "Google Maps".to_string(),
        timestamp: None,
        title: "Google Maps iOS database".to_string(),
        detail: format!("{} rows across {} tables — search history, offline maps", total, tables.len()),
        source_path: source,
        forensic_value: ForensicValue::High,
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
    fn matches_google_maps_paths() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/Application Support/Google/Maps/GMMAutocomplete.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_row_count() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Google");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("GMMAutocomplete.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE recents (q TEXT, ts INTEGER)", []).unwrap();
        c.execute("INSERT INTO recents VALUES ('123 main st', 1700000000)", []).unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Google");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("GMMAutocomplete.sqlite");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

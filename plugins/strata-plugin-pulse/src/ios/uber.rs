//! Uber iOS — `store.db` / `cache.db` under `*uber*` paths.
//!
//! Contains trip history with pickup/dropoff locations.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "uber")
        && util::name_is(path, &["store.db", "cache.db", "uber.db"])
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
        subcategory: "Uber".to_string(),
        timestamp: None,
        title: "Uber iOS database".to_string(),
        detail: format!("{} rows across {} tables — trip history, locations", total, tables.len()),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1430".to_string()),
        is_suspicious: false,
        raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_uber_paths() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/UberEats/store.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_table_count() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("uber");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE trips (id INTEGER PRIMARY KEY)", []).unwrap();
        c.execute("INSERT INTO trips DEFAULT VALUES", []).unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("uber");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

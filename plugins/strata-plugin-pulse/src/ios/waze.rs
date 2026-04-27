//! Waze iOS — `user.db`, `*.db` under `*waze*`.
//!
//! Contains search history, favorites, recent destinations.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    if !util::path_contains(path, "waze") {
        return false;
    }
    util::name_is(path, &["user.db", "waze.db"])
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
        subcategory: "Waze".to_string(),
        timestamp: None,
        title: "Waze iOS database".to_string(),
        detail: format!(
            "{} rows across {} tables — navigation history, favorites",
            total,
            tables.len()
        ),
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
    fn matches_waze_paths() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Library/Waze/user.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_rows() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("waze");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("user.db");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE favorites (id INTEGER PRIMARY KEY, name TEXT)",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO favorites (name) VALUES ('Home')", [])
            .unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("waze");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("user.db");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

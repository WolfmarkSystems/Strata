//! Clash of Clans iOS — `*.db` under `*supercell*` / `*clashofclans*`.
//!
//! Supercell games store player ID, clan membership, and chat in local
//! SQLite caches. Chat logs may contain comms evidence.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let scope = util::path_contains(path, "supercell") || util::path_contains(path, "clashofclans");
    if !scope {
        return false;
    }
    let n = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    n.ends_with(".db") || n.ends_with(".sqlite")
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
        subcategory: "Clash of Clans".to_string(),
        timestamp: None,
        title: "Clash of Clans / Supercell iOS database".to_string(),
        detail: format!(
            "{} rows across {} tables — player profile, clan, in-game chat",
            total,
            tables.len()
        ),
        source_path: source,
        forensic_value: ForensicValue::Medium,
        mitre_technique: Some("T1005".to_string()),
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
    fn matches_supercell_paths() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Library/supercell/store.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_rows() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("supercell");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("cache.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE chat (id INTEGER PRIMARY KEY, msg TEXT)", [])
            .unwrap();
        c.execute("INSERT INTO chat (msg) VALUES ('attack now')", [])
            .unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("clashofclans");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

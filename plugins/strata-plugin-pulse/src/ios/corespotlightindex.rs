//! iOS CoreSpotlight index — `*.indexDirectory/` SQLite stores.
//!
//! CoreSpotlight stores per-app searchable metadata (contact names,
//! message previews, document titles). Even after the source app
//! deletes content, the Spotlight index may retain the metadata.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "corespotlight") && {
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
        category: ArtifactCategory::SystemActivity,
        subcategory: "CoreSpotlight index".to_string(), timestamp: None,
        title: "iOS CoreSpotlight per-app search index".to_string(),
        detail: format!("{} rows — searchable metadata (may retain deleted content titles/previews)", total),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()), is_suspicious: false, raw_data: None,
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
    fn matches_corespotlight() {
        assert!(matches(Path::new("/var/mobile/Library/CoreSpotlight/NSFileProtectionComplete/index.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_rows() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("CoreSpotlight");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("index.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE searchable_items (id TEXT PRIMARY KEY, title TEXT)", []).unwrap();
        c.execute("INSERT INTO searchable_items VALUES ('i1', 'My Document')", []).unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("CoreSpotlight");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("index.db");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

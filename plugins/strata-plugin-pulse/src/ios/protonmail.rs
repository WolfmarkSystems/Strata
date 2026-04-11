//! ProtonMail iOS — `ProtonMail.sqlite`, `*.db` under `*protonmail*`.
//!
//! ProtonMail encrypts bodies server-side but caches envelope metadata
//! (sender, recipient, subject, date) in a local SQLite database.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["protonmail.sqlite"])
        || (util::path_contains(path, "protonmail") && {
            let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            n.ends_with(".sqlite") || n.ends_with(".db")
        })
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
        category: ArtifactCategory::Communications,
        subcategory: "ProtonMail".to_string(), timestamp: None,
        title: "ProtonMail iOS database".to_string(),
        detail: format!("{} rows across {} tables — encrypted email metadata cache", total, tables.len()),
        source_path: source, forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1114".to_string()), is_suspicious: false, raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_protonmail() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/ProtonMail.sqlite")));
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/ProtonMail/cache.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_rows() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("protonmail");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("cache.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE messages (id TEXT PRIMARY KEY, subject TEXT)", []).unwrap();
        c.execute("INSERT INTO messages VALUES ('a', 'Hello')", []).unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("protonmail");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("cache.db");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

//! iOS FileProvider — cloud file metadata from iCloud Drive, Dropbox, etc.
//!
//! `server.db` under `FileProvider/` contains indexed cloud file metadata.
//! Reveals file knowledge even after cloud-side deletion.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "/fileprovider/")
        && util::name_is(path, &["server.db", "enumerator.db"])
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
        category: ArtifactCategory::CloudSync,
        subcategory: "FileProvider".to_string(),
        timestamp: None,
        title: "iOS FileProvider cloud file index".to_string(),
        detail: format!("{} rows across {} tables — iCloud Drive / Dropbox / Google Drive metadata", total, tables.len()),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1530".to_string()),
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
    fn matches_fileprovider_paths() {
        assert!(matches(Path::new("/var/mobile/Library/Application Support/FileProvider/server.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/server.db")));
    }

    #[test]
    fn parses_rows() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Library").join("FileProvider");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("server.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, filename TEXT)", []).unwrap();
        c.execute("INSERT INTO items (filename) VALUES ('doc.pdf')", []).unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("iCloud Drive"));
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Library").join("FileProvider");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("server.db");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

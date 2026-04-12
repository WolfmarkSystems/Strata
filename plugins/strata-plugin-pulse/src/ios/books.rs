//! Apple Books — `BKLibrary-*.sqlite`, `BKAnnotation-*.sqlite`.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
    n.starts_with("bklibrary") && n.ends_with(".sqlite")
        || n.starts_with("bkannotation") && n.ends_with(".sqlite")
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
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let label = if name.to_ascii_lowercase().contains("annotation") {
        "book annotations (highlights, notes, bookmarks)"
    } else {
        "book library (purchases, downloads, reading progress)"
    };
    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Apple Books".to_string(), timestamp: None,
        title: format!("Apple Books: {}", label),
        detail: format!("{} rows — {}", total, label),
        source_path: source, forensic_value: ForensicValue::Medium,
        mitre_technique: None, is_suspicious: false, raw_data: None,
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
    fn matches_bklibrary() {
        assert!(matches(Path::new("/var/mobile/Media/Books/BKLibrary-1.sqlite")));
        assert!(matches(Path::new("/var/mobile/Media/Books/BKAnnotation-1.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_library() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("BKLibrary-1.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE ZBKLIBRARYASSET (Z_PK INTEGER PRIMARY KEY, ZTITLE TEXT)", []).unwrap();
        c.execute("INSERT INTO ZBKLIBRARYASSET (ZTITLE) VALUES ('Test Book')", []).unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("library"));
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("BKLibrary-1.sqlite");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

//! Instagram iOS — `DirectPhotos.sqlite`, `direct.db`, `*instagram*`.
//!
//! iLEAPP keys off several Instagram databases:
//!   * `DirectPhotos.sqlite` — DM photo metadata
//!   * `direct.db` — DM thread + message metadata
//!   * `Cookies.binarycookies` under `instagram` path
//!
//! Pulse v1.0 reports presence + row counts for known tables.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    let ig_scope = util::path_contains(path, "instagram");
    if util::name_is(path, &["directphotos.sqlite", "direct.db"]) {
        return true;
    }
    util::name_is(path, &["db.sqlite"]) && ig_scope
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
        category: ArtifactCategory::SocialMedia,
        subcategory: "Instagram".to_string(),
        timestamp: None,
        title: "Instagram iOS database".to_string(),
        detail: format!("{} rows across {} tables: {}", total, tables.len(), tables.join(", ")),
        source_path: source,
        forensic_value: ForensicValue::Critical,
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
    fn matches_instagram_filenames() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/Caches/DirectPhotos.sqlite")));
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/Application Support/Instagram/direct.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_table_count() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("DirectPhotos.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE photos (id INTEGER PRIMARY KEY, url TEXT)", []).unwrap();
        c.execute("INSERT INTO photos (url) VALUES ('https://ig.com/a.jpg')", []).unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("1 rows"));
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("DirectPhotos.sqlite");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

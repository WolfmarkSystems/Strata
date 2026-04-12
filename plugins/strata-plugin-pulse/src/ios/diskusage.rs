//! iOS disk usage — `CacheDeleteAppCache.db` / storage management.
//!
//! Shows per-app storage consumption + offloading decisions. An app
//! with 0 bytes but a large "Documents" allocation was recently
//! offloaded (possible evidence destruction awareness).

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["cachedeleteappcache.db", "storaged.db"])
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
        subcategory: "Disk usage".to_string(), timestamp: None,
        title: "iOS storage management / disk usage".to_string(),
        detail: format!("{} rows — per-app storage consumption, cache deletion, offloading decisions", total),
        source_path: source, forensic_value: ForensicValue::Medium,
        mitre_technique: Some("T1070".to_string()), is_suspicious: false, raw_data: None,
        confidence: 0,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;
    #[test]
    fn matches_cachedelete() {
        assert!(matches(Path::new("/var/mobile/Library/CacheDelete/CacheDeleteAppCache.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_rows() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE app_cache (id INTEGER PRIMARY KEY, bundle TEXT)", []).unwrap();
        c.execute("INSERT INTO app_cache (bundle) VALUES ('com.app')", []).unwrap();
        assert_eq!(parse(tmp.path()).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let _c = Connection::open(tmp.path()).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

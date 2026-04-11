//! iOS Siri — `assistant.db`, `siriknowledgeextractor.db`.
//!
//! Records Siri queries, responses, and learned suggestions. iLEAPP
//! keys off `ZASSISTANTINTERACTION` with query text + timestamp.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["assistant.db", "siriknowledgeextractor.db"])
        || (util::path_contains(path, "siri") && util::name_is(path, &["db.sqlite", "cache.db"]))
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
        subcategory: "Siri".to_string(), timestamp: None,
        title: "iOS Siri interactions".to_string(),
        detail: format!("{} rows across {} tables — voice queries, responses, learned suggestions", total, tables.len()),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()), is_suspicious: false, raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn matches_siri() {
        assert!(matches(Path::new("/var/mobile/Library/Assistant/assistant.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_rows() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE interactions (id INTEGER PRIMARY KEY, query TEXT)", []).unwrap();
        c.execute("INSERT INTO interactions (query) VALUES ('What time is it')", []).unwrap();
        assert_eq!(parse(tmp.path()).len(), 1);
    }
    #[test]
    fn empty_db_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let _c = Connection::open(tmp.path()).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

//! iOS CrashReporter deep — `DiagnosticMessages/` store,
//! `Analytics/*.ips.synced` metadata.
//!
//! Extends the basic `crashlogs.rs` by targeting the aggregated
//! analytics database that survives log rotation. iOS records per-app
//! crash counts, jetsam events, and exception types.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    let in_analytics = util::path_contains(path, "/analytics/")
        || util::path_contains(path, "/diagnosticmessages/")
        || util::path_contains(path, "/crashreporter/");
    in_analytics && util::name_is(path, &["analytics.db", "diagnosticmessages.db", "crashes.db"])
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
        subcategory: "CrashReporter analytics".to_string(), timestamp: None,
        title: "iOS CrashReporter analytics store".to_string(),
        detail: format!("{} rows across {} tables — aggregated crash counts, jetsam, exception types", total, tables.len()),
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
    fn matches_analytics_db() {
        assert!(matches(Path::new("/var/mobile/Library/Logs/CrashReporter/Analytics/analytics.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_rows() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Library").join("Logs").join("CrashReporter");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("analytics.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE crash_events (id INTEGER PRIMARY KEY, bundle TEXT, count INTEGER)", []).unwrap();
        c.execute("INSERT INTO crash_events (bundle, count) VALUES ('com.example', 3)", []).unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Library").join("DiagnosticMessages");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("diagnosticmessages.db");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

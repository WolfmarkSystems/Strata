//! iOS Screen Recording — `RPVideoLog.sqlite` / ReplayKit metadata.
//!
//! iOS logs screen recording sessions (start time, duration, app).
//! Proves the user was capturing screen at specific moments.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["rpvideolog.sqlite"])
        || (util::path_contains(path, "replaykit") && {
            let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            n.ends_with(".db") || n.ends_with(".sqlite")
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
        category: ArtifactCategory::UserActivity,
        subcategory: "Screen Recording".to_string(), timestamp: None,
        title: "iOS Screen Recording log".to_string(),
        detail: format!("{} rows across {} tables — recording sessions with start time, duration, source app", total, tables.len()),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: Some("T1113".to_string()), is_suspicious: false, raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn matches_screen_recording() {
        assert!(matches(Path::new("/var/mobile/Library/ReplayKit/RPVideoLog.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_rows() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE recordings (id INTEGER PRIMARY KEY, startTime DOUBLE, duration DOUBLE)", []).unwrap();
        c.execute("INSERT INTO recordings (startTime, duration) VALUES (700000000.0, 30.0)", []).unwrap();
        let recs = parse(tmp.path());
        assert_eq!(recs.len(), 1);
        assert!(recs[0].mitre_technique.as_deref() == Some("T1113"));
    }

    #[test]
    fn empty_db_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let _c = Connection::open(tmp.path()).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

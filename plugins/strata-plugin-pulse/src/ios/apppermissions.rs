//! iOS App Privacy Report (iOS 15+) — `com.apple.privacy.accounting.db`.
//!
//! Logs every time an app accesses camera, mic, location, contacts,
//! photos with exact timestamps. iLEAPP keys off the `access` table.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["com.apple.privacy.accounting.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "access") { return out; }
    let source = path.to_string_lossy().to_string();
    let total = util::count_rows(&conn, "access");

    let by_category = conn
        .prepare("SELECT COALESCE(category, '(unknown)'), COUNT(*) FROM access GROUP BY category ORDER BY COUNT(*) DESC")
        .and_then(|mut s| {
            let r = s.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "App Privacy Report".to_string(),
        timestamp: None,
        title: "iOS App Privacy Report".to_string(),
        detail: format!("{} access events (timestamped camera/mic/location/contacts access log)", total),
        source_path: source.clone(),
        forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
    });

    for (cat, count) in by_category.into_iter().take(10) {
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: format!("Privacy access: {}", cat),
            timestamp: None,
            title: format!("Privacy report — {}", cat),
            detail: format!("{} access events for category {}", count, cat),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_privacy_db(rows: &[(&str, &str)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE access (bundle_id TEXT, category TEXT, timestamp REAL, kind TEXT)", []).unwrap();
        for (bid, cat) in rows {
            c.execute("INSERT INTO access VALUES (?1, ?2, 700000000.0, 'access')", rusqlite::params![*bid, *cat]).unwrap();
        }
        tmp
    }

    #[test]
    fn matches_privacy_db() {
        assert!(matches(Path::new("/var/mobile/Library/com.apple.privacy.accounting.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_summary_and_category_breakdown() {
        let tmp = make_privacy_db(&[
            ("com.app.a", "Camera"), ("com.app.b", "Camera"),
            ("com.app.a", "Microphone"),
        ]);
        let recs = parse(tmp.path());
        let summary = recs.iter().find(|r| r.subcategory == "App Privacy Report").unwrap();
        assert!(summary.detail.contains("3 access events"));
        assert!(recs.iter().any(|r| r.subcategory == "Privacy access: Camera"));
        assert!(recs.iter().any(|r| r.subcategory == "Privacy access: Microphone"));
    }

    #[test]
    fn missing_access_table_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

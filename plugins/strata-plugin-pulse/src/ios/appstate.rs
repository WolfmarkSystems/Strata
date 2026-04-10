//! iOS `applicationState.db` — installed app metadata.
//!
//! Every installed app has a row in `application_identifier_tab` with
//! its bundle ID, and `key_tab` / `kvs` hold per-app state. iLEAPP
//! uses this to enumerate installed apps and their container paths.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["applicationstate.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "application_identifier_tab") { return out; }
    let source = path.to_string_lossy().to_string();
    let count = util::count_rows(&conn, "application_identifier_tab");

    out.push(ArtifactRecord {
        category: ArtifactCategory::ExecutionHistory,
        subcategory: "Application state".to_string(),
        timestamp: None,
        title: "iOS installed applications".to_string(),
        detail: format!("{} application_identifier_tab rows (installed + previously installed apps)", count),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn matches_appstate_filename() {
        assert!(matches(Path::new("/var/mobile/Library/FrontBoard/applicationState.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_app_count() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE application_identifier_tab (id INTEGER PRIMARY KEY, application_identifier TEXT)", []).unwrap();
        c.execute("INSERT INTO application_identifier_tab (application_identifier) VALUES ('com.apple.mobilesafari')", []).unwrap();
        c.execute("INSERT INTO application_identifier_tab (application_identifier) VALUES ('com.example.app')", []).unwrap();
        let recs = parse(tmp.path());
        let r = recs.iter().find(|r| r.subcategory == "Application state").unwrap();
        assert!(r.detail.contains("2 application_identifier_tab"));
    }

    #[test]
    fn missing_table_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

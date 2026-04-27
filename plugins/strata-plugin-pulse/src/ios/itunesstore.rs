//! iOS iTunes Store — `itunesstored2.sqlitedb`.
//!
//! Complete App Store purchase history with Apple ID. Proves account
//! ownership and app acquisition timeline.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["itunesstored2.sqlitedb", "itunesstored.sqlitedb"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    if util::table_exists(&conn, "purchase") {
        let count = util::count_rows(&conn, "purchase");
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "iTunes Store purchases".to_string(),
            timestamp: None,
            title: "App Store purchase history".to_string(),
            detail: format!(
                "{} purchase rows (app downloads with Apple ID + date)",
                count
            ),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
    }
    if util::table_exists(&conn, "account") {
        let count = util::count_rows(&conn, "account");
        out.push(ArtifactRecord {
            category: ArtifactCategory::AccountsCredentials,
            subcategory: "iTunes Store accounts".to_string(),
            timestamp: None,
            title: "iTunes Store accounts".to_string(),
            detail: format!("{} account rows (Apple ID records)", count),
            source_path: source,
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn matches_itunesstore_filenames() {
        assert!(matches(Path::new(
            "/var/mobile/Library/com.apple.itunesstored/itunesstored2.sqlitedb"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_purchase_and_account() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE purchase (pid INTEGER PRIMARY KEY, title TEXT, date REAL)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE account (dsid INTEGER PRIMARY KEY, account_name TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO purchase (title, date) VALUES ('MyApp', 700000000.0)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO account (account_name) VALUES ('user@apple.com')",
            [],
        )
        .unwrap();
        let recs = parse(tmp.path());
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "iTunes Store purchases"));
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "iTunes Store accounts"));
    }

    #[test]
    fn no_known_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

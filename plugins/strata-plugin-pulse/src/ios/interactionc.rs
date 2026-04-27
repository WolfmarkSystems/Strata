//! iOS InteractionC — `interactionC.db`.
//!
//! `interactionC.db` records cross-app contact interactions (who the
//! user communicates with most across Messages, Mail, FaceTime).
//! iLEAPP keys off `ZINTERACTIONS` and `ZCONTACTS` tables.
//! High value for building a communication graph.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["interactionc.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();
    let mut emitted = false;

    if util::table_exists(&conn, "ZINTERACTIONS") {
        let count = util::count_rows(&conn, "ZINTERACTIONS");
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "InteractionC interactions".to_string(),
            timestamp: None,
            title: "iOS contact interactions".to_string(),
            detail: format!(
                "{} ZINTERACTIONS rows (cross-app communication graph)",
                count
            ),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
        emitted = true;
    }
    if util::table_exists(&conn, "ZCONTACTS") {
        let count = util::count_rows(&conn, "ZCONTACTS");
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "InteractionC contacts".to_string(),
            timestamp: None,
            title: "iOS interaction contacts".to_string(),
            detail: format!("{} ZCONTACTS rows", count),
            source_path: source,
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
        emitted = true;
    }
    if !emitted {
        return Vec::new();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn matches_interactionc() {
        assert!(matches(Path::new(
            "/var/mobile/Library/CoreDuet/People/interactionC.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_interactions_and_contacts() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE ZINTERACTIONS (Z_PK INTEGER PRIMARY KEY, ZBUNDLEID TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE ZCONTACTS (Z_PK INTEGER PRIMARY KEY, ZIDENTIFIER TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO ZINTERACTIONS (ZBUNDLEID) VALUES ('com.apple.MobileSMS')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO ZCONTACTS (ZIDENTIFIER) VALUES ('+15551234567')",
            [],
        )
        .unwrap();
        let recs = parse(tmp.path());
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "InteractionC interactions"));
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "InteractionC contacts"));
    }

    #[test]
    fn no_known_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

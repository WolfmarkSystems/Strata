//! Threema iOS — `ThreemaData.sqlite`.
//!
//! End-to-end encrypted messenger. On-device DB has `ZMESSAGE`,
//! `ZCONVERSATION`, `ZCONTACT`. Unlike Signal, the local DB is
//! not SQLCipher-encrypted.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["threemadata.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();
    let mut emitted = false;

    if util::table_exists(&conn, "ZMESSAGE") {
        let count = util::count_rows(&conn, "ZMESSAGE");
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "Threema messages".to_string(), timestamp: None,
            title: "Threema messages".to_string(),
            detail: format!("{} ZMESSAGE rows", count),
            source_path: source.clone(), forensic_value: ForensicValue::Critical,
            mitre_technique: Some("T1005".to_string()), is_suspicious: false, raw_data: None,
            confidence: 0,
        });
        emitted = true;
    }
    if util::table_exists(&conn, "ZCONTACT") {
        let count = util::count_rows(&conn, "ZCONTACT");
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "Threema contacts".to_string(), timestamp: None,
            title: "Threema contacts".to_string(),
            detail: format!("{} ZCONTACT rows", count),
            source_path: source, forensic_value: ForensicValue::High,
            mitre_technique: None, is_suspicious: false, raw_data: None,
            confidence: 0,
        });
        emitted = true;
    }
    if !emitted { return Vec::new(); }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn matches_threema() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/ThreemaData.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_messages_and_contacts() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZMESSAGE (Z_PK INTEGER PRIMARY KEY, ZTEXT TEXT)", []).unwrap();
        c.execute("CREATE TABLE ZCONTACT (Z_PK INTEGER PRIMARY KEY, ZNAME TEXT)", []).unwrap();
        c.execute("INSERT INTO ZMESSAGE (ZTEXT) VALUES ('hi')", []).unwrap();
        c.execute("INSERT INTO ZCONTACT (ZNAME) VALUES ('Alice')", []).unwrap();
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory == "Threema messages"));
        assert!(recs.iter().any(|r| r.subcategory == "Threema contacts"));
    }
    #[test]
    fn no_known_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

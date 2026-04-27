//! Kik Messenger iOS — `kik.sqlite`.
//!
//! iLEAPP keys off `ZKIKMESSAGE` (messages) and `ZKIKUSER` (contacts).
//! Timestamps are Cocoa seconds.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["kik.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    if util::table_exists(&conn, "ZKIKMESSAGE") {
        let count = util::count_rows(&conn, "ZKIKMESSAGE");
        let ts = conn
            .prepare("SELECT MIN(ZRECEIVEDTIMESTAMP), MAX(ZRECEIVEDTIMESTAMP) FROM ZKIKMESSAGE WHERE ZRECEIVEDTIMESTAMP > 0")
            .and_then(|mut s| s.query_row([], |r| Ok((r.get::<_, Option<f64>>(0)?, r.get::<_, Option<f64>>(1)?))))
            .unwrap_or((None, None));
        let first = ts.0.and_then(util::cf_absolute_to_unix);
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "Kik messages".to_string(),
            timestamp: first,
            title: "Kik Messenger messages".to_string(),
            detail: format!("{} ZKIKMESSAGE rows", count),
            source_path: source.clone(),
            forensic_value: ForensicValue::Critical,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
    }
    if util::table_exists(&conn, "ZKIKUSER") {
        let count = util::count_rows(&conn, "ZKIKUSER");
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "Kik users".to_string(),
            timestamp: None,
            title: "Kik Messenger contacts".to_string(),
            detail: format!("{} ZKIKUSER rows", count),
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
    fn matches_kik_filename() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Library/kik.sqlite"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_messages_and_users() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZKIKMESSAGE (Z_PK INTEGER PRIMARY KEY, ZBODY TEXT, ZRECEIVEDTIMESTAMP DOUBLE)", []).unwrap();
        c.execute(
            "CREATE TABLE ZKIKUSER (Z_PK INTEGER PRIMARY KEY, ZDISPLAYNAME TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO ZKIKMESSAGE (ZBODY, ZRECEIVEDTIMESTAMP) VALUES ('hi', 700000000.0)",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO ZKIKUSER (ZDISPLAYNAME) VALUES ('Alice')", [])
            .unwrap();
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory == "Kik messages"));
        assert!(recs.iter().any(|r| r.subcategory == "Kik users"));
    }

    #[test]
    fn missing_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

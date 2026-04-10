//! LINE Messenger iOS — `Line.sqlite`, `talk.sqlite`.
//!
//! LINE stores messages in `ZMESSAGE` (CoreData) with `ZTIMESTAMP`
//! (Cocoa seconds) and contacts in `ZUSER`.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    (util::name_is(path, &["line.sqlite", "talk.sqlite"]) && util::path_contains(path, "line"))
        || (util::name_is(path, &["line.sqlite"]))
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();
    let mut emitted = false;

    if util::table_exists(&conn, "ZMESSAGE") {
        let count = util::count_rows(&conn, "ZMESSAGE");
        let ts = conn
            .prepare("SELECT MIN(ZTIMESTAMP), MAX(ZTIMESTAMP) FROM ZMESSAGE WHERE ZTIMESTAMP > 0")
            .and_then(|mut s| s.query_row([], |r| Ok((r.get::<_, Option<f64>>(0)?, r.get::<_, Option<f64>>(1)?))))
            .unwrap_or((None, None));
        let first = ts.0.and_then(util::cf_absolute_to_unix);
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "LINE messages".to_string(),
            timestamp: first,
            title: "LINE Messenger messages".to_string(),
            detail: format!("{} ZMESSAGE rows", count),
            source_path: source.clone(),
            forensic_value: ForensicValue::Critical,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
        });
        emitted = true;
    }
    if util::table_exists(&conn, "ZUSER") {
        let count = util::count_rows(&conn, "ZUSER");
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "LINE contacts".to_string(),
            timestamp: None,
            title: "LINE Messenger contacts".to_string(),
            detail: format!("{} ZUSER rows", count),
            source_path: source,
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
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
    fn matches_line_filenames() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/Application Support/Line/line.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_messages_and_users() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZMESSAGE (Z_PK INTEGER PRIMARY KEY, ZTEXT TEXT, ZTIMESTAMP DOUBLE)", []).unwrap();
        c.execute("CREATE TABLE ZUSER (Z_PK INTEGER PRIMARY KEY, ZNAME TEXT)", []).unwrap();
        c.execute("INSERT INTO ZMESSAGE (ZTEXT, ZTIMESTAMP) VALUES ('hi', 700000000.0)", []).unwrap();
        c.execute("INSERT INTO ZUSER (ZNAME) VALUES ('Bob')", []).unwrap();
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory == "LINE messages"));
        assert!(recs.iter().any(|r| r.subcategory == "LINE contacts"));
    }

    #[test]
    fn missing_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

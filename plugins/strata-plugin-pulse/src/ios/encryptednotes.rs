//! iOS Encrypted Notes metadata — `NoteStore.sqlite` locked notes.
//!
//! Extends `notes.rs` by detecting which notes are password-locked.
//! The `ZICCLOUDSYNCINGOBJECT.ZISPASSWORDPROTECTED` flag marks
//! locked notes. Even though the body is encrypted, the existence
//! of locked notes + their creation date is forensically significant.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["notestore.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "ZICCLOUDSYNCINGOBJECT") { return out; }
    let source = path.to_string_lossy().to_string();

    let locked: i64 = conn
        .prepare("SELECT COUNT(*) FROM ZICCLOUDSYNCINGOBJECT WHERE ZISPASSWORDPROTECTED = 1")
        .and_then(|mut s| s.query_row([], |r| r.get(0)))
        .unwrap_or(0);

    if locked == 0 { return out; }

    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Encrypted Notes".to_string(), timestamp: None,
        title: "iOS password-locked Notes".to_string(),
        detail: format!("{} notes are password-protected (body encrypted, but existence + creation date visible)", locked),
        source_path: source, forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1027".to_string()),
        is_suspicious: true,
        raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_notestore(locked: usize, unlocked: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY, ZTITLE1 TEXT, ZISPASSWORDPROTECTED INTEGER)", []).unwrap();
        for i in 0..locked {
            c.execute("INSERT INTO ZICCLOUDSYNCINGOBJECT (ZTITLE1, ZISPASSWORDPROTECTED) VALUES (?1, 1)",
                rusqlite::params![format!("locked{}", i)]).unwrap();
        }
        for i in 0..unlocked {
            c.execute("INSERT INTO ZICCLOUDSYNCINGOBJECT (ZTITLE1, ZISPASSWORDPROTECTED) VALUES (?1, 0)",
                rusqlite::params![format!("open{}", i)]).unwrap();
        }
        tmp
    }

    #[test]
    fn detects_locked_notes_as_suspicious() {
        let tmp = make_notestore(3, 5);
        let recs = parse(tmp.path());
        assert_eq!(recs.len(), 1);
        assert!(recs[0].is_suspicious);
        assert!(recs[0].detail.contains("3 notes are password-protected"));
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }

    #[test]
    fn no_locked_notes_returns_empty() {
        let tmp = make_notestore(0, 5);
        assert!(parse(tmp.path()).is_empty());
    }

    #[test]
    fn missing_table_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}

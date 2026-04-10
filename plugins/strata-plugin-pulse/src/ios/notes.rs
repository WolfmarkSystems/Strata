//! iOS Notes — `notes.sqlite` (legacy) + `NoteStore.sqlite` (modern).
//!
//! iOS shipped two distinct schemas:
//!   * `notes.sqlite` (iOS <9): rows in `ZNOTE` with `ZTITLE` and
//!     `ZSUMMARY`.
//!   * `NoteStore.sqlite` (iOS 9+): rows in
//!     `ZICCLOUDSYNCINGOBJECT` keyed by Z_ENT == note entity, with
//!     `ZTITLE1` (or similar). Note bodies live in `ZNOTEDATA.ZDATA`,
//!     gzip-compressed protobufs that v1.0 deliberately doesn't decode.
//!
//! Pulse v1.0 emits the database presence + a count and date range.
//! Note-body extraction is queued for v1.1.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["notestore.sqlite", "notes.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    // iOS 9+ NoteStore: ZICCLOUDSYNCINGOBJECT contains every note,
    // folder, account, etc. We can't filter by entity without joining
    // Z_PRIMARYKEY at v1.0, so we just count rows. iLEAPP filters with
    // `WHERE ZICCLOUDSYNCINGOBJECT.ZNOTE != ''` against ZNOTEDATA.
    if util::table_exists(&conn, "ZICCLOUDSYNCINGOBJECT") {
        let count = util::count_rows(&conn, "ZICCLOUDSYNCINGOBJECT");
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Notes (modern)".to_string(),
            timestamp: None,
            title: "iOS Notes (NoteStore)".to_string(),
            detail: format!(
                "{} ZICCLOUDSYNCINGOBJECT rows (notes, folders, accounts; bodies are gzipped protobufs in ZNOTEDATA, not decoded in v1.0)",
                count
            ),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
        });
    }

    // Legacy iOS Notes.
    if util::table_exists(&conn, "ZNOTE") {
        let count = util::count_rows(&conn, "ZNOTE");
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Notes (legacy)".to_string(),
            timestamp: None,
            title: "iOS Notes (legacy)".to_string(),
            detail: format!("{} ZNOTE rows (legacy iOS notes schema)", count),
            source_path: source,
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
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

    fn make_modern_notestore(rows: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE ZICCLOUDSYNCINGOBJECT (\
                Z_PK INTEGER PRIMARY KEY, \
                ZTITLE1 TEXT, \
                ZSNIPPET TEXT \
             )",
            [],
        )
        .unwrap();
        for i in 0..rows {
            c.execute(
                "INSERT INTO ZICCLOUDSYNCINGOBJECT (ZTITLE1, ZSNIPPET) VALUES (?1, 'snippet')",
                rusqlite::params![format!("Note {}", i)],
            )
            .unwrap();
        }
        tmp
    }

    fn make_legacy_notes(rows: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE ZNOTE (Z_PK INTEGER PRIMARY KEY, ZTITLE TEXT, ZSUMMARY TEXT)",
            [],
        )
        .unwrap();
        for i in 0..rows {
            c.execute(
                "INSERT INTO ZNOTE (ZTITLE, ZSUMMARY) VALUES (?1, 'summary')",
                rusqlite::params![format!("Old Note {}", i)],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_both_schemas() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Notes/NoteStore.sqlite"
        )));
        assert!(matches(Path::new("/var/mobile/Library/Notes/notes.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_modern_schema_with_count() {
        let tmp = make_modern_notestore(5);
        let records = parse(tmp.path());
        let modern = records
            .iter()
            .find(|r| r.subcategory == "Notes (modern)")
            .expect("modern record");
        assert!(modern.detail.contains("5 ZICCLOUDSYNCINGOBJECT"));
        assert!(modern.detail.contains("not decoded in v1.0"));
    }

    #[test]
    fn parses_legacy_schema_with_count() {
        let tmp = make_legacy_notes(2);
        let records = parse(tmp.path());
        let legacy = records
            .iter()
            .find(|r| r.subcategory == "Notes (legacy)")
            .expect("legacy record");
        assert!(legacy.detail.contains("2 ZNOTE"));
    }

    #[test]
    fn unknown_schema_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        assert!(parse(tmp.path()).is_empty());
    }
}

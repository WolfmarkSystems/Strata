//! iOS Voice Memos — `Recordings.db`, `CloudRecordings.db`.
//!
//! `ZCLOUDRECORDING` has title, creation date (Cocoa seconds),
//! duration, label preset. May reveal evidentiary recordings.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["recordings.db", "cloudrecordings.db"])
        && util::path_contains(path, "voicememos")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();

    for table in ["ZCLOUDRECORDING", "ZRECORDING"] {
        if !util::table_exists(&conn, table) { continue; }
        let count = util::count_rows(&conn, table);
        let ts = conn
            .prepare(&format!("SELECT MIN(ZCREATIONDATE), MAX(ZCREATIONDATE) FROM {} WHERE ZCREATIONDATE IS NOT NULL", table))
            .and_then(|mut s| s.query_row([], |r| Ok((r.get::<_, Option<f64>>(0)?, r.get::<_, Option<f64>>(1)?))))
            .unwrap_or((None, None));
        let first = ts.0.and_then(util::cf_absolute_to_unix);
        out.push(ArtifactRecord {
            category: ArtifactCategory::Media,
            subcategory: "Voice Memos".to_string(),
            timestamp: first,
            title: "iOS Voice Memos recordings".to_string(),
            detail: format!("{} {} rows (audio recording metadata, not bytes)", count, table),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
        });
        break; // Only emit one — both tables are schema variants
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_voicememos_paths() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/com.apple.voicememos/Recordings.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/Recordings.db")));
    }

    #[test]
    fn parses_recording_count_and_timestamp() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("com.apple.voicememos");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("Recordings.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE ZCLOUDRECORDING (Z_PK INTEGER PRIMARY KEY, ZTITLE TEXT, ZCREATIONDATE DOUBLE, ZDURATION DOUBLE)", []).unwrap();
        c.execute("INSERT INTO ZCLOUDRECORDING (ZTITLE, ZCREATIONDATE, ZDURATION) VALUES ('memo1', 700000000.0, 30.0)", []).unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("1 ZCLOUDRECORDING"));
        assert_eq!(recs[0].timestamp, Some(700_000_000 + util::APPLE_EPOCH_OFFSET));
    }

    #[test]
    fn no_recording_tables_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("com.apple.voicememos");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("Recordings.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}

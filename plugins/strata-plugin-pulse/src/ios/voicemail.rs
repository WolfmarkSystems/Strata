//! iOS visual voicemail — `voicemail.db`.
//!
//! `voicemail.db` lives under `Library/Voicemail/`. The relevant
//! table is `voicemail` with columns `ROWID`, `remote_uid`, `date`
//! (Unix epoch — *not* Cocoa), `sender`, `callback_num`, `duration`,
//! `expiration`, `trashed_date`, `flags`.
//!
//! v1.0 reports total messages, distinct senders, and the date range.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["voicemail.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "voicemail") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let count = util::count_rows(&conn, "voicemail");

    let (first, last): (Option<i64>, Option<i64>) = conn
        .prepare("SELECT MIN(date), MAX(date) FROM voicemail WHERE date IS NOT NULL")
        .and_then(|mut s| {
            s.query_row([], |row| {
                Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?))
            })
        })
        .unwrap_or((None, None));

    let distinct_senders: i64 = conn
        .prepare("SELECT COUNT(DISTINCT sender) FROM voicemail WHERE sender IS NOT NULL")
        .and_then(|mut s| s.query_row([], |row| row.get(0)))
        .unwrap_or(0);

    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "Voicemail".to_string(),
        timestamp: first,
        title: "iOS visual voicemail".to_string(),
        detail: format!(
            "{} voicemail rows, {} distinct senders, range {:?}..{:?} Unix",
            count, distinct_senders, first, last
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_voicemail_db(rows: &[(&str, i64)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE voicemail (\
                ROWID INTEGER PRIMARY KEY, \
                sender TEXT, \
                date INTEGER, \
                duration INTEGER, \
                trashed_date INTEGER \
             )",
            [],
        )
        .unwrap();
        for (sender, date) in rows {
            c.execute(
                "INSERT INTO voicemail (sender, date, duration) VALUES (?1, ?2, 30)",
                rusqlite::params![*sender, *date],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_voicemail_filename() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Voicemail/voicemail.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_count_distinct_senders_and_range() {
        let tmp = make_voicemail_db(&[
            ("+15551112222", 1_700_000_000),
            ("+15551112222", 1_700_000_500),
            ("+15553334444", 1_700_001_000),
        ]);
        let recs = parse(tmp.path());
        let v = recs.iter().find(|r| r.subcategory == "Voicemail").unwrap();
        assert!(v.detail.contains("3 voicemail"));
        assert!(v.detail.contains("2 distinct senders"));
        assert_eq!(v.timestamp, Some(1_700_000_000));
    }

    #[test]
    fn empty_db_emits_summary_with_zero() {
        let tmp = make_voicemail_db(&[]);
        let recs = parse(tmp.path());
        let v = recs.iter().find(|r| r.subcategory == "Voicemail").unwrap();
        assert!(v.detail.contains("0 voicemail"));
    }

    #[test]
    fn missing_table_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        assert!(parse(tmp.path()).is_empty());
    }
}

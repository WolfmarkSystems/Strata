//! Snapchat iOS — `gallery.encrypted.db` and `arroyo.db`.
//!
//! Snapchat encrypts most of its on-device storage. The two SQLite
//! files iLEAPP keys off:
//!   * `gallery.encrypted.db` — Memories metadata (file paths,
//!     timestamps), even when the actual media bytes are encrypted.
//!   * `arroyo.db` — newer (2023+) chat backbone with `messages`
//!     and `conversation_messages` tables.
//!
//! Pulse v1.0 reports presence + table counts when the database is
//! readable.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["gallery.encrypted.db", "arroyo.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    let table_names: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .and_then(|mut s| {
            let r = s.query_map([], |row| row.get::<_, String>(0))?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    if table_names.is_empty() {
        return out;
    }

    let mut total = 0_i64;
    for t in &table_names {
        total += util::count_rows(&conn, t);
    }
    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "Snapchat".to_string(),
        timestamp: None,
        title: "Snapchat iOS database".to_string(),
        detail: format!(
            "Snapchat database present, {} rows across {} table(s): {}",
            total,
            table_names.len(),
            table_names.join(", ")
        ),
        source_path: source,
        forensic_value: ForensicValue::Critical,
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

    fn make_snap_db(rows: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, body BLOB)",
            [],
        )
        .unwrap();
        for i in 0..rows {
            c.execute(
                "INSERT INTO messages (body) VALUES (?1)",
                rusqlite::params![format!("ciphertext {}", i)],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_snapchat_filenames() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Snapchat/gallery.encrypted.db"
        )));
        assert!(matches(Path::new("/copies/arroyo.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_table_count_and_total_rows() {
        let tmp = make_snap_db(4);
        let recs = parse(tmp.path());
        let r = recs.iter().find(|r| r.subcategory == "Snapchat").unwrap();
        assert!(r.detail.contains("4 rows"));
        assert!(r.detail.contains("messages"));
    }

    #[test]
    fn empty_database_returns_no_records() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let _c = Connection::open(tmp.path()).unwrap();
        }
        assert!(parse(tmp.path()).is_empty());
    }
}

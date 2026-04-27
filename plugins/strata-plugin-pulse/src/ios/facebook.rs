//! Facebook Messenger iOS — `lightspeed-*.db`, `threads_db2`.
//!
//! Facebook Messenger stores DMs in `lightspeed-*.db` (newer builds)
//! and `threads_db2` (legacy). iLEAPP keys off `messages` and
//! `threads` tables. The schema varies heavily per build; Pulse v1.0
//! does a table inventory.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    n.starts_with("lightspeed") && n.ends_with(".db")
        || n == "threads_db2"
        || (n == "fbmessenger.db" || n == "messenger.db")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .and_then(|mut s| {
            let r = s.query_map([], |row| row.get::<_, String>(0))?;
            Ok(r.flatten().collect())
        })
        .unwrap_or_default();
    if tables.is_empty() {
        return out;
    }

    let mut total = 0_i64;
    for t in &tables {
        total += util::count_rows(&conn, t);
    }

    // Try to detect messages specifically
    let msg_count = if util::table_exists(&conn, "messages") {
        util::count_rows(&conn, "messages")
    } else {
        0
    };

    let detail = if msg_count > 0 {
        format!(
            "{} messages rows, {} total rows across {} tables",
            msg_count,
            total,
            tables.len()
        )
    } else {
        format!("{} total rows across {} tables", total, tables.len())
    };

    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "Facebook Messenger".to_string(),
        timestamp: None,
        title: "Facebook Messenger iOS database".to_string(),
        detail,
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
    use tempfile::tempdir;

    #[test]
    fn matches_messenger_filenames() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Documents/lightspeed-abc123.db"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Library/threads_db2"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_messages_table_when_present() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("lightspeed-test.db");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT)",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO messages (text) VALUES ('hello')", [])
            .unwrap();
        c.execute("INSERT INTO messages (text) VALUES ('world')", [])
            .unwrap();
        let recs = parse(&p);
        let r = recs
            .iter()
            .find(|r| r.subcategory == "Facebook Messenger")
            .unwrap();
        assert!(r.detail.contains("2 messages rows"));
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("threads_db2");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}

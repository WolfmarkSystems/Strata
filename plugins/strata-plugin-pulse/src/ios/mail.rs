//! iOS / macOS Mail — `Envelope Index` SQLite database.
//!
//! Apple Mail keeps the message index in `Envelope Index` (no
//! extension). The relevant tables iLEAPP keys off:
//!   * `messages` — one row per message (`subject_id`, `sender`,
//!     `date_sent`, `date_received`, `mailbox`)
//!   * `subjects` — distinct subject lookup
//!   * `addresses` — sender/recipient lookup
//!   * `mailboxes` — mailbox metadata

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    n == "envelope index"
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "messages") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let messages = util::count_rows(&conn, "messages");

    let (first, last): (Option<i64>, Option<i64>) = conn
        .prepare("SELECT MIN(date_received), MAX(date_received) FROM messages WHERE date_received IS NOT NULL")
        .and_then(|mut s| s.query_row([], |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?))))
        .unwrap_or((None, None));

    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "Mail".to_string(),
        timestamp: first,
        title: "Apple Mail Envelope Index".to_string(),
        detail: format!(
            "{} messages, range {:?}..{:?} Unix",
            messages, first, last
        ),
        source_path: source.clone(),
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1114".to_string()),
        is_suspicious: false,
        raw_data: None,
    });

    for (table, label) in [
        ("addresses", "Mail addresses"),
        ("subjects", "Mail subjects"),
        ("mailboxes", "Mail mailboxes"),
    ] {
        if util::table_exists(&conn, table) {
            let n = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::Communications,
                subcategory: format!("Mail {}", table),
                timestamp: None,
                title: label.to_string(),
                detail: format!("{} {} rows", n, table),
                source_path: source.clone(),
                forensic_value: ForensicValue::Medium,
                mitre_technique: None,
                is_suspicious: false,
                raw_data: None,
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn make_envelope(messages: usize) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let p = dir.path().join("Envelope Index");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE messages (ROWID INTEGER PRIMARY KEY, sender INTEGER, date_received INTEGER)", []).unwrap();
        c.execute("CREATE TABLE addresses (ROWID INTEGER PRIMARY KEY, address TEXT)", []).unwrap();
        c.execute("CREATE TABLE subjects (ROWID INTEGER PRIMARY KEY, subject TEXT)", []).unwrap();
        c.execute("CREATE TABLE mailboxes (ROWID INTEGER PRIMARY KEY, url TEXT)", []).unwrap();
        for i in 0..messages {
            c.execute(
                "INSERT INTO messages (sender, date_received) VALUES (1, ?1)",
                rusqlite::params![1_700_000_000_i64 + i as i64],
            )
            .unwrap();
        }
        (dir, p)
    }

    #[test]
    fn matches_envelope_index() {
        assert!(matches(Path::new(
            "/Users/me/Library/Mail/V8/MailData/Envelope Index"
        )));
        assert!(!matches(Path::new("/Users/me/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_message_count_and_range() {
        let (_d, p) = make_envelope(3);
        let recs = parse(&p);
        let m = recs.iter().find(|r| r.subcategory == "Mail").unwrap();
        assert!(m.detail.contains("3 messages"));
        assert_eq!(m.timestamp, Some(1_700_000_000));
    }

    #[test]
    fn missing_messages_table_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("Envelope Index");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}

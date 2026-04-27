//! MeetMe — chat extraction.
//!
//! ALEAPP reference: `scripts/artifacts/meetme.py`. Source path:
//! `/data/data/com.myyearbook.m/databases/chats.db`.
//!
//! Key tables: `messages`, `members`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.myyearbook.m/databases/chats.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "messages") {
        return Vec::new();
    }
    read_messages(&conn, path)
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    // Try joining with members table first for name enrichment
    let sql_joined = "SELECT m.sent_at, m.thread_id, members.first_name, \
                      members.last_name, m.sent_by, m.body, m.type, m.local_path \
                      FROM messages m \
                      LEFT JOIN members ON members.member_id = m.sent_by \
                      ORDER BY m.sent_at DESC LIMIT 10000";
    if let Ok(mut stmt) = conn.prepare(sql_joined) {
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Option<i64>>(0).unwrap_or(None),
                row.get::<_, Option<i64>>(1).unwrap_or(None),
                row.get::<_, Option<String>>(2).unwrap_or(None),
                row.get::<_, Option<String>>(3).unwrap_or(None),
                row.get::<_, Option<i64>>(4).unwrap_or(None),
                row.get::<_, Option<String>>(5).unwrap_or(None),
                row.get::<_, Option<String>>(6).unwrap_or(None),
                row.get::<_, Option<String>>(7).unwrap_or(None),
            ))
        });
        if let Ok(rows) = rows {
            let mut out = Vec::new();
            for (sent_at, thread_id, first, last, sender, body, msg_type, local) in rows.flatten() {
                let ts = sent_at.and_then(unix_ms_to_i64);
                let sender_id = sender.unwrap_or(0);
                let first = first.unwrap_or_default();
                let last = last.unwrap_or_default();
                let name = format!("{} {}", first, last).trim().to_string();
                let name = if name.is_empty() {
                    format!("user_{}", sender_id)
                } else {
                    name
                };
                let body = body.unwrap_or_default();
                let kind = msg_type.unwrap_or_else(|| "text".to_string());
                let thread = thread_id.unwrap_or(0);
                let local_path = local.unwrap_or_default();
                let preview: String = body.chars().take(120).collect();
                let title = format!("MeetMe {}: {}", name, preview);
                let mut detail = format!(
                    "MeetMe message sender='{}' thread={} type='{}' body='{}'",
                    name, thread, kind, body
                );
                if !local_path.is_empty() {
                    detail.push_str(&format!(" attachment='{}'", local_path));
                }
                out.push(build_record(
                    ArtifactCategory::SocialMedia,
                    "MeetMe Message",
                    title,
                    detail,
                    path,
                    ts,
                    ForensicValue::High,
                    false,
                ));
            }
            return out;
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE members (
                member_id INTEGER,
                first_name TEXT,
                last_name TEXT
            );
            INSERT INTO members VALUES(100,'Alice','Smith');
            INSERT INTO members VALUES(200,'Bob','Jones');
            CREATE TABLE messages (
                sent_at INTEGER,
                thread_id INTEGER,
                sent_by INTEGER,
                body TEXT,
                type TEXT,
                local_path TEXT
            );
            INSERT INTO messages VALUES(1609459200000,1,100,'Hi from Alice','text',NULL);
            INSERT INTO messages VALUES(1609459300000,1,200,'Hi Alice','text',NULL);
            INSERT INTO messages VALUES(1609459400000,1,100,'pic','image','/local/pic.jpg');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_messages() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "MeetMe Message"));
    }

    #[test]
    fn sender_name_enriched() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Alice Smith")));
        assert!(r.iter().any(|a| a.title.contains("Bob Jones")));
    }

    #[test]
    fn attachment_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("attachment='/local/pic.jpg'")));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}

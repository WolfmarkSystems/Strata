//! Twitter/X — Android tweet and DM extraction.
//!
//! ALEAPP reference: `scripts/artifacts/Twitter.py`. Source paths:
//! - `/data/data/com.twitter.android/databases/*.db`
//!
//! Key tables: `statuses` (tweets), `conversations` (DMs).

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.twitter.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "statuses") {
        out.extend(read_statuses(&conn, path));
    }
    if table_exists(&conn, "conversations") {
        out.extend(read_conversations(&conn, path));
    }
    out
}

fn read_statuses(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT author_id, content, created, in_r_user_id \
               FROM statuses WHERE content IS NOT NULL \
               ORDER BY created DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (author, content, created_ms, reply_to) in rows.flatten() {
        let author = author.unwrap_or_else(|| "(unknown)".to_string());
        let body = content.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("Tweet by {}: {}", author, preview);
        let mut detail = format!("Twitter status author='{}' content='{}'", author, body);
        if let Some(r) = reply_to.filter(|r| !r.is_empty()) {
            detail.push_str(&format!(" reply_to='{}'", r));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Twitter Status",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn read_conversations(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT conversation_id, last_readable_event_time, \
               title, participant_count \
               FROM conversations \
               ORDER BY last_readable_event_time DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (conv_id, last_event, title, participants) in rows.flatten() {
        let conv = conv_id.unwrap_or_else(|| "(unknown)".to_string());
        let ts = last_event.and_then(unix_ms_to_i64);
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let count = participants.unwrap_or(0);
        let title_out = format!("Twitter DM: {} ({} participants)", title_str, count);
        let detail = format!(
            "Twitter conversation id='{}' title='{}' participants={}",
            conv, title_str, count
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Twitter DM",
            title_out,
            detail,
            path,
            ts,
            ForensicValue::High,
            false,
        ));
    }
    out
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
            CREATE TABLE statuses (
                _id INTEGER PRIMARY KEY,
                author_id TEXT,
                content TEXT,
                created INTEGER,
                in_r_user_id TEXT
            );
            INSERT INTO statuses VALUES(1,'user_abc','Hello Twitter!',1609459200000,NULL);
            INSERT INTO statuses VALUES(2,'user_abc','@someone Check this',1609459300000,'someone');
            INSERT INTO statuses VALUES(3,'user_xyz','RT: Important news',1609459400000,NULL);
            CREATE TABLE conversations (
                conversation_id TEXT,
                last_readable_event_time INTEGER,
                title TEXT,
                participant_count INTEGER
            );
            INSERT INTO conversations VALUES('conv_001',1609459500000,'Chat with Bob',2);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_statuses_and_conversations() {
        let db = make_db();
        let r = parse(db.path());
        let tweets: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Twitter Status")
            .collect();
        let dms: Vec<_> = r.iter().filter(|a| a.subcategory == "Twitter DM").collect();
        assert_eq!(tweets.len(), 3);
        assert_eq!(dms.len(), 1);
    }

    #[test]
    fn reply_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("reply_to='someone'")));
    }

    #[test]
    fn content_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Hello Twitter!")));
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

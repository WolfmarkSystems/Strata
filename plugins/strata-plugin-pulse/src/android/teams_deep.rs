//! Microsoft Teams — deep channel messages, shared files, and meeting chat.
//!
//! Source path: `/data/data/com.microsoft.teams/databases/`.
//!
//! Schema note: not in ALEAPP upstream. Teams stores channel messages,
//! shared documents, and meeting chat separately from the main message DB.
//! This parser targets those supplemental tables for investigative depth.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.microsoft.teams/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["channel_messages", "channelmessages", "channel_message"] {
        if table_exists(&conn, table) {
            out.extend(read_channel_messages(&conn, path, table));
            break;
        }
    }
    for table in &["shared_files", "sharedfiles", "file_shares"] {
        if table_exists(&conn, table) {
            out.extend(read_shared_files(&conn, path, table));
            break;
        }
    }
    for table in &["meeting_chat", "meetingchat", "meeting_messages"] {
        if table_exists(&conn, table) {
            out.extend(read_meeting_chat(&conn, path, table));
            break;
        }
    }
    out
}

fn read_channel_messages(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT channel_id, channel_name, team_name, sender, body, sent_at \
         FROM \"{t}\" ORDER BY sent_at DESC LIMIT 10000",
        t = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (channel_id, channel_name, team_name, sender, body, ts_ms) in rows.flatten() {
        let channel_id = channel_id.unwrap_or_default();
        let channel_name = channel_name.unwrap_or_else(|| "(unknown channel)".to_string());
        let team_name = team_name.unwrap_or_default();
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let body = body.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(100).collect();
        let title = format!("Teams [{}] {}: {}", channel_name, sender, preview);
        let detail = format!(
            "Teams channel_message channel_id='{}' channel_name='{}' team_name='{}' sender='{}' body='{}'",
            channel_id, channel_name, team_name, sender, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Teams Channel Message",
            title,
            detail,
            path,
            ts,
            ForensicValue::High,
            false,
        ));
    }
    out
}

fn read_shared_files(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT file_name, file_type, size, shared_by, channel_id \
         FROM \"{t}\" ORDER BY rowid DESC LIMIT 5000",
        t = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (file_name, file_type, size, shared_by, channel_id) in rows.flatten() {
        let file_name = file_name.unwrap_or_else(|| "(unknown)".to_string());
        let file_type = file_type.unwrap_or_default();
        let size = size.unwrap_or(0);
        let shared_by = shared_by.unwrap_or_default();
        let channel_id = channel_id.unwrap_or_default();
        let title = format!("Teams file: {} shared by {}", file_name, shared_by);
        let detail = format!(
            "Teams shared_file file_name='{}' file_type='{}' size={} shared_by='{}' channel_id='{}'",
            file_name, file_type, size, shared_by, channel_id
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Teams Shared File",
            title,
            detail,
            path,
            None,
            ForensicValue::High,
            false,
        ));
    }
    out
}

fn read_meeting_chat(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT meeting_id, sender, body, sent_at \
         FROM \"{t}\" ORDER BY sent_at DESC LIMIT 10000",
        t = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (meeting_id, sender, body, ts_ms) in rows.flatten() {
        let meeting_id = meeting_id.unwrap_or_default();
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let body = body.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(100).collect();
        let title = format!("Teams meeting chat {}: {}", sender, preview);
        let detail = format!(
            "Teams meeting_chat meeting_id='{}' sender='{}' body='{}'",
            meeting_id, sender, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Teams Meeting Chat",
            title,
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
            CREATE TABLE channel_messages (
                channel_id TEXT,
                channel_name TEXT,
                team_name TEXT,
                sender TEXT,
                body TEXT,
                sent_at INTEGER
            );
            INSERT INTO channel_messages VALUES('Ch1','general','Engineering','alice','Deploy is ready',1609459200000);
            CREATE TABLE shared_files (
                file_name TEXT,
                file_type TEXT,
                size INTEGER,
                shared_by TEXT,
                channel_id TEXT
            );
            INSERT INTO shared_files VALUES('design.docx','docx',51200,'bob','Ch1');
            CREATE TABLE meeting_chat (
                meeting_id TEXT,
                sender TEXT,
                body TEXT,
                sent_at INTEGER
            );
            INSERT INTO meeting_chat VALUES('M001','carol','Can everyone hear me?',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_channel_files_meeting() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Teams Channel Message"));
        assert!(r.iter().any(|a| a.subcategory == "Teams Shared File"));
        assert!(r.iter().any(|a| a.subcategory == "Teams Meeting Chat"));
    }

    #[test]
    fn channel_message_has_team_and_sender() {
        let db = make_db();
        let r = parse(db.path());
        let m = r.iter().find(|a| a.subcategory == "Teams Channel Message").unwrap();
        assert!(m.detail.contains("team_name='Engineering'"));
        assert!(m.detail.contains("sender='alice'"));
    }

    #[test]
    fn shared_file_size_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let f = r.iter().find(|a| a.subcategory == "Teams Shared File").unwrap();
        assert!(f.detail.contains("size=51200"));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}

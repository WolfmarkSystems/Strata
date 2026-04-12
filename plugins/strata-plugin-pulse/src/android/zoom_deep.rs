//! Zoom — deep meeting history, chat messages, and recordings.
//!
//! Source path: `/data/data/us.zoom.videomeetings/databases/`.
//!
//! Schema note: not in ALEAPP upstream. Zoom caches meeting attendance,
//! in-meeting chat, and local recording metadata. Meeting topics and chat
//! are Critical forensic value — they establish who was present, when,
//! and what was discussed.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["us.zoom.videomeetings/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["meeting_history", "meetinghistory", "meetings"] {
        if table_exists(&conn, table) {
            out.extend(read_meeting_history(&conn, path, table));
            break;
        }
    }
    for table in &["chat_messages", "chatmessages", "meeting_chat"] {
        if table_exists(&conn, table) {
            out.extend(read_chat_messages(&conn, path, table));
            break;
        }
    }
    for table in &["recordings", "local_recordings", "meeting_recordings"] {
        if table_exists(&conn, table) {
            out.extend(read_recordings(&conn, path, table));
            break;
        }
    }
    out
}

fn read_meeting_history(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT meeting_id, topic, host, start_time, duration, participants_count \
         FROM \"{t}\" ORDER BY start_time DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (meeting_id, topic, host, start_time_ms, duration, participants) in rows.flatten() {
        let meeting_id = meeting_id.unwrap_or_default();
        let topic = topic.unwrap_or_else(|| "(no topic)".to_string());
        let host = host.unwrap_or_default();
        let duration = duration.unwrap_or(0);
        let participants = participants.unwrap_or(0);
        let ts = start_time_ms.and_then(unix_ms_to_i64);
        let title = format!("Zoom meeting: {} (host: {})", topic, host);
        let detail = format!(
            "Zoom meeting_history meeting_id='{}' topic='{}' host='{}' duration={}s participants_count={}",
            meeting_id, topic, host, duration, participants
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Zoom Meeting",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

fn read_chat_messages(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
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
        let title = format!("Zoom chat {}: {}", sender, preview);
        let detail = format!(
            "Zoom chat_message meeting_id='{}' sender='{}' body='{}'",
            meeting_id, sender, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Zoom Chat",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

fn read_recordings(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT meeting_id, file_path, file_size, recorded_at \
         FROM \"{t}\" ORDER BY recorded_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (meeting_id, file_path, file_size, ts_ms) in rows.flatten() {
        let meeting_id = meeting_id.unwrap_or_default();
        let file_path = file_path.unwrap_or_default();
        let file_size = file_size.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Zoom recording: meeting {}", meeting_id);
        let detail = format!(
            "Zoom recording meeting_id='{}' file_path='{}' file_size={}",
            meeting_id, file_path, file_size
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Zoom Recording",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
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
            CREATE TABLE meeting_history (
                meeting_id TEXT,
                topic TEXT,
                host TEXT,
                start_time INTEGER,
                duration INTEGER,
                participants_count INTEGER
            );
            INSERT INTO meeting_history VALUES('83542961','Q1 Planning','alice@corp.com',1609459200000,3600,12);
            CREATE TABLE chat_messages (
                meeting_id TEXT,
                sender TEXT,
                body TEXT,
                sent_at INTEGER
            );
            INSERT INTO chat_messages VALUES('83542961','bob','Can you share your screen?',1609459500000);
            CREATE TABLE recordings (
                meeting_id TEXT,
                file_path TEXT,
                file_size INTEGER,
                recorded_at INTEGER
            );
            INSERT INTO recordings VALUES('83542961','/storage/emulated/0/zoom/recording.mp4',524288000,1609463000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_meeting_chat_recording() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Zoom Meeting"));
        assert!(r.iter().any(|a| a.subcategory == "Zoom Chat"));
        assert!(r.iter().any(|a| a.subcategory == "Zoom Recording"));
    }

    #[test]
    fn meeting_topic_in_title() {
        let db = make_db();
        let r = parse(db.path());
        let m = r.iter().find(|a| a.subcategory == "Zoom Meeting").unwrap();
        assert!(m.title.contains("Q1 Planning"));
        assert!(m.detail.contains("participants_count=12"));
    }

    #[test]
    fn recording_file_size_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let rec = r.iter().find(|a| a.subcategory == "Zoom Recording").unwrap();
        assert!(rec.detail.contains("file_size=524288000"));
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

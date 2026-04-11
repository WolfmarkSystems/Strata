//! Twitter/X Spaces — audio room history extraction.
//!
//! Source path: `/data/data/com.twitter.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Complements `twitter.rs` which
//! covers tweets/DMs. Spaces are stored in tables like `audiospace`,
//! `audio_space_events`, or `spaces_history`. Key fields: host, title,
//! participant count, recording status.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.twitter.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["audiospace", "audio_space", "spaces_history"] {
        if table_exists(&conn, table) {
            out.extend(read_spaces(&conn, path, table));
            break;
        }
    }
    out
}

fn read_spaces(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT space_id, host_user_id, host_name, title, \
         started_at, ended_at, participant_count, is_recording, state \
         FROM \"{table}\" ORDER BY started_at DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (space_id, host_id, host_name, space_title, started_ms, _ended_ms, participants, is_recording, state) in rows.flatten() {
        let space_id = space_id.unwrap_or_else(|| "(unknown)".to_string());
        let host_id = host_id.unwrap_or_default();
        let host_name = host_name.unwrap_or_default();
        let space_title = space_title.unwrap_or_default();
        let participants = participants.unwrap_or(0);
        let is_recording = is_recording.unwrap_or(0) != 0;
        let state = state.unwrap_or_default();
        let ts = started_ms.and_then(unix_ms_to_i64);
        let title = format!("X Space: {} ({} participants)", space_title, participants);
        let detail = format!(
            "Twitter Space space_id='{}' host_id='{}' host_name='{}' title='{}' participant_count={} recording={} state='{}'",
            space_id, host_id, host_name, space_title, participants, is_recording, state
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Twitter Space",
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
            CREATE TABLE audiospace (
                space_id TEXT,
                host_user_id TEXT,
                host_name TEXT,
                title TEXT,
                started_at INTEGER,
                ended_at INTEGER,
                participant_count INTEGER,
                is_recording INTEGER,
                state TEXT
            );
            INSERT INTO audiospace VALUES('sp1','u1','Alice','Tech Talk',1609459200000,1609462800000,250,1,'ended');
            INSERT INTO audiospace VALUES('sp2','u2','Bob','Live Q&A',1609545600000,NULL,100,0,'live');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_spaces() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Twitter Space"));
    }

    #[test]
    fn participant_count_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("250 participants")));
    }

    #[test]
    fn recording_flag_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("recording=true") && a.detail.contains("state='ended'")));
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

//! LINE — Android message and call extraction.
//!
//! ALEAPP reference: `scripts/artifacts/line.py`. Source path:
//! `/data/data/jp.naver.line.android/databases/naver_line`.
//!
//! Key tables: `chat_history` (messages), `contacts`, `call_history`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["jp.naver.line.android/databases/naver_line"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "chat_history") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "call_history") {
        out.extend(read_calls(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT from_mid, content, created_time, chat_id, \
               attachement_type \
               FROM chat_history WHERE content IS NOT NULL \
               ORDER BY created_time DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        // Fallback: older schema uses different column names
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (from, content, created_ms, chat_id, attach_type) in rows.flatten() {
        let from = from.unwrap_or_else(|| "(unknown)".to_string());
        let body = content.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let chat = chat_id.unwrap_or_else(|| "(unknown)".to_string());
        let attach = attach_type.unwrap_or(0);
        let preview: String = body.chars().take(120).collect();
        let title = format!("LINE {}: {}", from, preview);
        let mut detail = format!(
            "LINE message from='{}' chat='{}' body='{}'",
            from, chat, body
        );
        if attach != 0 {
            detail.push_str(&format!(" attachment_type={}", attach));
        }
        out.push(build_record(
            ArtifactCategory::Communications,
            "LINE Message",
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

fn read_calls(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT caller_mid, call_type, start_time, end_time, voip_type \
               FROM call_history ORDER BY start_time DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (caller, call_type, start_ms, end_ms, voip) in rows.flatten() {
        let caller = caller.unwrap_or_else(|| "(unknown)".to_string());
        let ts = start_ms.and_then(unix_ms_to_i64);
        let direction = match call_type.as_deref() {
            Some(t) if t.ends_with('O') => "outgoing",
            _ => "incoming",
        };
        let dur = match (start_ms, end_ms) {
            (Some(s), Some(e)) if e > s => (e - s) / 1000,
            _ => 0,
        };
        let voip_type = voip.unwrap_or_else(|| "voice".to_string());
        let title = format!("LINE {} call {} ({}s)", voip_type, direction, dur);
        let detail = format!(
            "LINE call caller='{}' direction={} type='{}' duration={}s",
            caller, direction, voip_type, dur
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "LINE Call",
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
            CREATE TABLE chat_history (
                _id INTEGER PRIMARY KEY,
                from_mid TEXT,
                content TEXT,
                created_time INTEGER,
                chat_id TEXT,
                attachement_type INTEGER
            );
            INSERT INTO chat_history VALUES(1,'u001','Hello LINE!',1609459200000,'c100',0);
            INSERT INTO chat_history VALUES(2,'u002','Photo attached',1609459300000,'c100',1);
            INSERT INTO chat_history VALUES(3,'u001','Group msg',1609459400000,'c200',0);
            CREATE TABLE call_history (
                caller_mid TEXT,
                call_type TEXT,
                start_time INTEGER,
                end_time INTEGER,
                voip_type TEXT
            );
            INSERT INTO call_history VALUES('u001','AUDIO_O',1609459500000,1609459620000,'voice');
            INSERT INTO call_history VALUES('u002','VIDEO_I',1609459700000,1609459760000,'video');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_calls() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "LINE Message")
            .collect();
        let calls: Vec<_> = r.iter().filter(|a| a.subcategory == "LINE Call").collect();
        assert_eq!(msgs.len(), 3);
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn attachment_type_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("attachment_type=1")));
    }

    #[test]
    fn call_direction_from_type() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.subcategory == "LINE Call" && a.detail.contains("direction=outgoing")));
        assert!(r
            .iter()
            .any(|a| a.subcategory == "LINE Call" && a.detail.contains("direction=incoming")));
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

//! BetterHelp — online therapy app session and message data.
//!
//! Source path: `/data/data/com.betterhelp/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. BetterHelp stores therapist
//! info, chat messages, and scheduled sessions.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.betterhelp/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "therapist") {
        out.extend(read_therapists(&conn, path));
    }
    if table_exists(&conn, "session") {
        out.extend(read_sessions(&conn, path));
    }
    if table_exists(&conn, "message") {
        out.extend(read_messages(&conn, path));
    }
    out
}

fn read_therapists(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, license_number, specialty, email \
               FROM therapist LIMIT 100";
    let mut stmt = match conn.prepare(sql) {
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, license_number, specialty, email) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let license_number = license_number.unwrap_or_default();
        let specialty = specialty.unwrap_or_default();
        let email = email.unwrap_or_default();
        let title = format!("BetterHelp therapist: {}", name);
        let detail = format!(
            "BetterHelp therapist id='{}' name='{}' license='{}' specialty='{}' email='{}'",
            id, name, license_number, specialty, email
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "BetterHelp Therapist",
            title,
            detail,
            path,
            None,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

fn read_sessions(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, therapist_id, scheduled_at, session_type, \
               status, duration_minutes \
               FROM session ORDER BY scheduled_at DESC LIMIT 5000";
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, therapist_id, ts_ms, session_type, status, duration) in rows.flatten() {
        let id = id.unwrap_or_default();
        let therapist_id = therapist_id.unwrap_or_default();
        let session_type = session_type.unwrap_or_else(|| "(unknown)".to_string());
        let status = status.unwrap_or_default();
        let duration = duration.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("BetterHelp session: {} ({} min)", session_type, duration);
        let detail = format!(
            "BetterHelp session id='{}' therapist_id='{}' type='{}' status='{}' duration_minutes={}",
            id, therapist_id, session_type, status, duration
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "BetterHelp Session",
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

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, sender, recipient, content, sent_at, is_from_therapist \
               FROM message ORDER BY sent_at DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, sender, recipient, content, ts_ms, from_therapist) in rows.flatten() {
        let id = id.unwrap_or_default();
        let sender = sender.unwrap_or_default();
        let recipient = recipient.unwrap_or_default();
        let content = content.unwrap_or_default();
        let from_therapist = from_therapist.unwrap_or(0) != 0;
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = content.chars().take(120).collect();
        let title = format!("BetterHelp msg {}: {}", sender, preview);
        let detail = format!(
            "BetterHelp message id='{}' sender='{}' recipient='{}' body='{}' from_therapist={}",
            id, sender, recipient, content, from_therapist
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "BetterHelp Message",
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
            CREATE TABLE therapist (
                id TEXT,
                name TEXT,
                license_number TEXT,
                specialty TEXT,
                email TEXT
            );
            INSERT INTO therapist VALUES('t1','Dr. Smith','LIC12345','Anxiety','smith@bh.com');
            CREATE TABLE session (
                id TEXT,
                therapist_id TEXT,
                scheduled_at INTEGER,
                session_type TEXT,
                status TEXT,
                duration_minutes INTEGER
            );
            INSERT INTO session VALUES('s1','t1',1609459200000,'video','scheduled',45);
            CREATE TABLE message (
                id TEXT,
                sender TEXT,
                recipient TEXT,
                content TEXT,
                sent_at INTEGER,
                is_from_therapist INTEGER
            );
            INSERT INTO message VALUES('m1','t1','client','How are you feeling today?',1609459300000,1);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_therapist_session_message() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "BetterHelp Therapist"));
        assert!(r.iter().any(|a| a.subcategory == "BetterHelp Session"));
        assert!(r.iter().any(|a| a.subcategory == "BetterHelp Message"));
    }

    #[test]
    fn therapist_license_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("license='LIC12345'")));
    }

    #[test]
    fn from_therapist_flag_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("from_therapist=true")));
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

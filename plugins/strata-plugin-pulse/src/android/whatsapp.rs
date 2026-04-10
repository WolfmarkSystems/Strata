//! WhatsApp — Android message, call, and contact extraction.
//!
//! ALEAPP reference: `scripts/artifacts/WhatsApp.py`. Source paths:
//! - `/data/data/com.whatsapp/databases/msgstore.db` — messages & calls
//! - `/data/data/com.whatsapp/databases/wa.db` — contacts
//!
//! Message schema (msgstore.db):
//! ```sql
//! CREATE TABLE messages (
//!   _id INTEGER PRIMARY KEY,
//!   key_remote_jid TEXT,
//!   key_from_me INTEGER,
//!   data TEXT,
//!   timestamp INTEGER,     -- ms since epoch
//!   media_mime_type TEXT,
//!   media_size INTEGER,
//!   received_timestamp INTEGER,
//!   remote_resource TEXT
//! );
//! ```

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.whatsapp/databases/msgstore.db", "com.whatsapp/databases/wa.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let p = path.to_string_lossy().to_lowercase();
    let mut out = Vec::new();
    if p.contains("msgstore") {
        if table_exists(&conn, "messages") {
            out.extend(read_messages(&conn, path));
        }
        if table_exists(&conn, "call_log") {
            out.extend(read_calls(&conn, path));
        }
    }
    if p.contains("wa.db") && table_exists(&conn, "wa_contacts") {
        out.extend(read_contacts(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT key_remote_jid, key_from_me, data, timestamp, \
               media_mime_type, remote_resource \
               FROM messages WHERE data IS NOT NULL \
               ORDER BY timestamp DESC LIMIT 10000";
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (jid, from_me, data, ts_ms, mime, remote) in rows.flatten() {
        let direction = if from_me.unwrap_or(0) == 1 { "sent" } else { "received" };
        let jid = jid.unwrap_or_else(|| "(unknown)".to_string());
        let body = data.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("WhatsApp {} {}: {}", direction, jid, preview);
        let mut detail = format!(
            "WhatsApp message direction={} jid='{}' body='{}'",
            direction, jid, body
        );
        if let Some(m) = mime.filter(|m| !m.is_empty()) {
            detail.push_str(&format!(" media_type='{}'", m));
        }
        if let Some(r) = remote.filter(|r| !r.is_empty()) {
            detail.push_str(&format!(" sender_in_group='{}'", r));
        }
        out.push(build_record(
            ArtifactCategory::Communications,
            "WhatsApp Message",
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
    let sql = "SELECT timestamp, video_call, duration, call_result \
               FROM call_log ORDER BY timestamp DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, video, duration, result) in rows.flatten() {
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let call_type = if video.unwrap_or(0) == 1 { "video" } else { "voice" };
        let dur = duration.unwrap_or(0);
        let res = result.unwrap_or(0);
        let title = format!("WhatsApp {} call ({}s, result={})", call_type, dur, res);
        let detail = format!(
            "WhatsApp call type={} duration={}s result={}",
            call_type, dur, res
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "WhatsApp Call",
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

fn read_contacts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT jid, display_name, number, status \
               FROM wa_contacts WHERE is_whatsapp_user = 1 \
               ORDER BY display_name LIMIT 10000";
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (jid, name, number, status) in rows.flatten() {
        let jid = jid.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(no name)".to_string());
        let title = format!("WhatsApp contact: {} ({})", name, jid);
        let mut detail = format!("WhatsApp contact jid='{}' name='{}'", jid, name);
        if let Some(n) = number.filter(|n| !n.is_empty()) {
            detail.push_str(&format!(" number='{}'", n));
        }
        if let Some(s) = status.filter(|s| !s.is_empty()) {
            detail.push_str(&format!(" status='{}'", s));
        }
        out.push(build_record(
            ArtifactCategory::Communications,
            "WhatsApp Contact",
            title,
            detail,
            path,
            None,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_msgstore() -> tempfile::NamedTempFile {
        let tmp = tempfile::Builder::new()
            .suffix("msgstore.db")
            .tempfile()
            .unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE messages (
                _id INTEGER PRIMARY KEY,
                key_remote_jid TEXT,
                key_from_me INTEGER,
                data TEXT,
                timestamp INTEGER,
                media_mime_type TEXT,
                media_size INTEGER,
                remote_resource TEXT
            );
            INSERT INTO messages VALUES(1,'5551234567@s.whatsapp.net',0,'Hello there',1609459200000,NULL,0,NULL);
            INSERT INTO messages VALUES(2,'5551234567@s.whatsapp.net',1,'Hi back',1609459300000,NULL,0,NULL);
            INSERT INTO messages VALUES(3,'group-123@g.us',0,'Group msg',1609459400000,'image/jpeg',12345,'5559999999@s.whatsapp.net');
            CREATE TABLE call_log (
                _id INTEGER PRIMARY KEY,
                timestamp INTEGER,
                video_call INTEGER,
                duration INTEGER,
                call_result INTEGER
            );
            INSERT INTO call_log VALUES(1,1609459500000,0,120,0);
            INSERT INTO call_log VALUES(2,1609459600000,1,30,0);
            "#,
        )
        .unwrap();
        tmp
    }

    fn make_wa_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::Builder::new()
            .suffix("wa.db")
            .tempfile()
            .unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE wa_contacts (
                jid TEXT,
                display_name TEXT,
                number TEXT,
                status TEXT,
                is_whatsapp_user INTEGER
            );
            INSERT INTO wa_contacts VALUES('5551234567@s.whatsapp.net','Alice','+15551234567','Hey there!',1);
            INSERT INTO wa_contacts VALUES('5559999999@s.whatsapp.net','Bob','+15559999999',NULL,1);
            INSERT INTO wa_contacts VALUES('nonuser@s.whatsapp.net','Charlie','+15550000000',NULL,0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_calls() {
        let db = make_msgstore();
        let r = parse(db.path());
        let msgs: Vec<_> = r.iter().filter(|a| a.subcategory == "WhatsApp Message").collect();
        let calls: Vec<_> = r.iter().filter(|a| a.subcategory == "WhatsApp Call").collect();
        assert_eq!(msgs.len(), 3);
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn direction_is_correct() {
        let db = make_msgstore();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("received")));
        assert!(r.iter().any(|a| a.title.contains("sent")));
    }

    #[test]
    fn group_message_includes_sender() {
        let db = make_msgstore();
        let r = parse(db.path());
        let grp = r.iter().find(|a| a.detail.contains("group-123")).unwrap();
        assert!(grp.detail.contains("sender_in_group='5559999999@s.whatsapp.net'"));
    }

    #[test]
    fn contacts_excludes_non_whatsapp_users() {
        let db = make_wa_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "WhatsApp Contact"));
        assert!(!r.iter().any(|a| a.detail.contains("Charlie")));
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

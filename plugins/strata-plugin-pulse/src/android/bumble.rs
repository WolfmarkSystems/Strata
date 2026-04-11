//! Bumble — dating app message and match extraction.
//!
//! ALEAPP reference: `scripts/artifacts/bumble.py`. Source path:
//! `/data/data/com.bumble.app/databases/ChatComDatabase`.
//!
//! Key tables: `message`, `conversation_info`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.bumble.app/databases/chatcomdatabase"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "message") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "conversation_info") {
        out.extend(read_matches(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT sender_id, recipient_id, created_timestamp, \
               payload, payload_type, is_incoming, conversation_id \
               FROM message \
               ORDER BY created_timestamp DESC LIMIT 10000";
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
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (sender, recipient, ts_ms, payload, payload_type, is_incoming, conv) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let recipient = recipient.unwrap_or_else(|| "(unknown)".to_string());
        let payload = payload.unwrap_or_default();
        let kind = payload_type.unwrap_or_else(|| "text".to_string());
        let direction = if is_incoming.unwrap_or(0) == 1 { "incoming" } else { "outgoing" };
        let conv = conv.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = payload.chars().take(120).collect();
        let title = format!("Bumble {} {}: {}", direction, sender, preview);
        let detail = format!(
            "Bumble message direction={} sender='{}' recipient='{}' type='{}' conversation='{}' payload='{}'",
            direction, sender, recipient, kind, conv, payload
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Bumble Message",
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

fn game_mode_name(code: i64) -> &'static str {
    match code {
        0 => "Date",
        1 => "Friends",
        2 => "Bizz",
        _ => "Unknown",
    }
}

fn read_matches(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT user_id, user_name, age, gender, game_mode \
               FROM conversation_info LIMIT 5000";
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (uid, name, age, gender, game_mode) in rows.flatten() {
        let uid = uid.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(no name)".to_string());
        let mode = game_mode_name(game_mode.unwrap_or(-1));
        let title = format!("Bumble match: {} ({})", name, mode);
        let mut detail = format!(
            "Bumble match id='{}' name='{}' game_mode='{}'",
            uid, name, mode
        );
        if let Some(a) = age {
            detail.push_str(&format!(" age={}", a));
        }
        if let Some(g) = gender.filter(|g| !g.is_empty()) {
            detail.push_str(&format!(" gender='{}'", g));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Bumble Match",
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

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE message (
                sender_id TEXT,
                recipient_id TEXT,
                created_timestamp INTEGER,
                payload TEXT,
                payload_type TEXT,
                is_incoming INTEGER,
                conversation_id TEXT,
                id TEXT
            );
            INSERT INTO message VALUES('u1','u2',1609459200000,'Hello match','text',0,'conv1','m1');
            INSERT INTO message VALUES('u2','u1',1609459300000,'Hi!','text',1,'conv1','m2');
            CREATE TABLE conversation_info (
                user_id TEXT,
                user_name TEXT,
                age INTEGER,
                gender TEXT,
                game_mode INTEGER,
                user_image_url TEXT,
                encrypted_user_id TEXT
            );
            INSERT INTO conversation_info VALUES('u2','Alice',28,'female',0,NULL,NULL);
            INSERT INTO conversation_info VALUES('u3','Bob',32,'male',1,NULL,NULL);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_matches() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r.iter().filter(|a| a.subcategory == "Bumble Message").collect();
        let matches: Vec<_> = r.iter().filter(|a| a.subcategory == "Bumble Match").collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn game_mode_mapped() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Bumble match: Alice (Date)")));
        assert!(r.iter().any(|a| a.title.contains("Bumble match: Bob (Friends)")));
    }

    #[test]
    fn direction_mapped() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("outgoing")));
        assert!(r.iter().any(|a| a.title.contains("incoming")));
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

//! Plenty of Fish — dating app matches, messages, and profile views.
//!
//! Source path: `/data/data/com.pof.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. POF uses Room databases with
//! tables like `match`, `message`, `profile_view`, `conversation`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.pof.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["match", "matches", "conversation"] {
        if table_exists(&conn, table) {
            out.extend(read_matches(&conn, path, table));
            break;
        }
    }
    for table in &["message", "messages", "chat_message"] {
        if table_exists(&conn, table) {
            out.extend(read_messages(&conn, path, table));
            break;
        }
    }
    for table in &["profile_view", "profile_views", "viewed_profile"] {
        if table_exists(&conn, table) {
            out.extend(read_profile_views(&conn, path, table));
            break;
        }
    }
    out
}

fn read_matches(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, user_id, username, age, matched_at \
         FROM \"{table}\" ORDER BY matched_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, user_id, username, age, matched_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let user_id = user_id.unwrap_or_default();
        let username = username.unwrap_or_else(|| "(no name)".to_string());
        let ts = matched_ms.and_then(unix_ms_to_i64);
        let title = format!("POF match: {}", username);
        let mut detail = format!(
            "POF match id='{}' user_id='{}' username='{}'",
            id, user_id, username
        );
        if let Some(a) = age {
            detail.push_str(&format!(" age={}", a));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "POF Match",
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

fn read_messages(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, sender_id, recipient_id, body, sent_at, is_incoming \
         FROM \"{table}\" ORDER BY sent_at DESC LIMIT 10000",
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, sender, recipient, body, sent_ms, is_incoming) in rows.flatten() {
        let id = id.unwrap_or_default();
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let recipient = recipient.unwrap_or_else(|| "(unknown)".to_string());
        let body = body.unwrap_or_default();
        let direction = if is_incoming.unwrap_or(0) == 1 { "incoming" } else { "outgoing" };
        let ts = sent_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("POF {} msg {}: {}", direction, sender, preview);
        let detail = format!(
            "POF message id='{}' sender='{}' recipient='{}' direction='{}' body='{}'",
            id, sender, recipient, direction, body
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "POF Message",
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

fn read_profile_views(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT user_id, username, viewed_at \
         FROM \"{table}\" ORDER BY viewed_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (user_id, username, viewed_ms) in rows.flatten() {
        let user_id = user_id.unwrap_or_default();
        let username = username.unwrap_or_else(|| "(no name)".to_string());
        let ts = viewed_ms.and_then(unix_ms_to_i64);
        let title = format!("POF profile viewed: {}", username);
        let detail = format!(
            "POF profile view user_id='{}' username='{}'",
            user_id, username
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "POF Profile View",
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE "match" (
                id TEXT,
                user_id TEXT,
                username TEXT,
                age INTEGER,
                matched_at INTEGER
            );
            INSERT INTO "match" VALUES('m1','u1','Jessica',29,1609459200000);
            CREATE TABLE message (
                id TEXT,
                sender_id TEXT,
                recipient_id TEXT,
                body TEXT,
                sent_at INTEGER,
                is_incoming INTEGER
            );
            INSERT INTO message VALUES('msg1','u1','me','Hey there!',1609459300000,1);
            CREATE TABLE profile_view (
                user_id TEXT,
                username TEXT,
                viewed_at INTEGER
            );
            INSERT INTO profile_view VALUES('u2','Mike',1609459100000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_matches_messages_profile_views() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "POF Match"));
        assert!(r.iter().any(|a| a.subcategory == "POF Message"));
        assert!(r.iter().any(|a| a.subcategory == "POF Profile View"));
    }

    #[test]
    fn match_age_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "POF Match" && a.detail.contains("age=29")));
    }

    #[test]
    fn message_direction_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "POF Message" && a.detail.contains("direction='incoming'")));
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

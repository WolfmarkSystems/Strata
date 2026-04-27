//! Coffee Meets Bagel — connections (matches) and messages.
//!
//! Source path: `/data/data/com.coffeemeetsbagel/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Coffee Meets Bagel uses Room databases
//! with tables like `connection`, `message`, `match`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.coffeemeetsbagel/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["connection", "connections", "match", "matches"] {
        if table_exists(&conn, table) {
            out.extend(read_connections(&conn, path, table));
            break;
        }
    }
    for table in &["message", "messages", "chat_message"] {
        if table_exists(&conn, table) {
            out.extend(read_messages(&conn, path, table));
            break;
        }
    }
    out
}

fn read_connections(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, match_name, connected_at, is_expired \
         FROM \"{table}\" ORDER BY connected_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, match_name, connected_ms, is_expired) in rows.flatten() {
        let id = id.unwrap_or_default();
        let match_name = match_name.unwrap_or_else(|| "(no name)".to_string());
        let expired = is_expired.unwrap_or(0) != 0;
        let ts = connected_ms.and_then(unix_ms_to_i64);
        let title = format!("CMB connection: {}", match_name);
        let detail = format!(
            "Coffee Meets Bagel connection id='{}' match_name='{}' expired={}",
            id, match_name, expired
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "CMB Connection",
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

fn read_messages(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, sender_id, connection_id, body, sent_at, is_incoming \
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
    for (id, sender, connection_id, body, sent_ms, is_incoming) in rows.flatten() {
        let id = id.unwrap_or_default();
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let connection_id = connection_id.unwrap_or_default();
        let body = body.unwrap_or_default();
        let direction = if is_incoming.unwrap_or(0) == 1 {
            "incoming"
        } else {
            "outgoing"
        };
        let ts = sent_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("CMB {} msg {}: {}", direction, sender, preview);
        let detail = format!(
            "Coffee Meets Bagel message id='{}' sender='{}' connection_id='{}' direction='{}' body='{}'",
            id, sender, connection_id, direction, body
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "CMB Message",
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
            CREATE TABLE connection (
                id TEXT,
                match_name TEXT,
                connected_at INTEGER,
                is_expired INTEGER
            );
            INSERT INTO connection VALUES('c1','Sarah',1609459200000,0);
            INSERT INTO connection VALUES('c2','James',1609372800000,1);
            CREATE TABLE message (
                id TEXT,
                sender_id TEXT,
                connection_id TEXT,
                body TEXT,
                sent_at INTEGER,
                is_incoming INTEGER
            );
            INSERT INTO message VALUES('m1','s1','c1','Hello, nice to meet you!',1609459300000,0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_connections_and_messages() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "CMB Connection"));
        assert!(r.iter().any(|a| a.subcategory == "CMB Message"));
    }

    #[test]
    fn expired_connection_flagged() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.subcategory == "CMB Connection" && a.detail.contains("expired=true")));
        assert!(r
            .iter()
            .any(|a| a.subcategory == "CMB Connection" && a.detail.contains("expired=false")));
    }

    #[test]
    fn message_body_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("Hello, nice to meet you!")));
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

//! Skype — Android message and call extraction.
//!
//! ALEAPP reference: `scripts/artifacts/skype.py`. Source path:
//! `/data/data/com.skype.raider/databases/live:*`.
//!
//! Key tables: `chatitem`, `person`, `user`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.skype.raider/databases/live",
    "com.skype.raider/databases/s4l-",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "chatitem") {
        out.extend(read_messages(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT conversation_id, from_id, timestamp, content, message_type \
               FROM chatitem WHERE content IS NOT NULL \
               ORDER BY timestamp DESC LIMIT 10000";
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
    for (conv, from, ts_ms, content, msg_type) in rows.flatten() {
        let conv = conv.unwrap_or_else(|| "(unknown)".to_string());
        let from = from.unwrap_or_else(|| "(unknown)".to_string());
        let body = content.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let is_call = msg_type.unwrap_or(0) == 3;
        let subcategory = if is_call {
            "Skype Call"
        } else {
            "Skype Message"
        };
        let preview: String = body.chars().take(120).collect();
        let title = format!("Skype {}: {}", from, preview);
        let detail = format!(
            "Skype {} from='{}' conversation='{}' body='{}'",
            if is_call { "call" } else { "message" },
            from,
            conv,
            body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            subcategory,
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
            CREATE TABLE chatitem (
                _id INTEGER PRIMARY KEY,
                conversation_id TEXT,
                from_id TEXT,
                timestamp INTEGER,
                content TEXT,
                message_type INTEGER
            );
            INSERT INTO chatitem VALUES(1,'19:abc@thread','live:user1',1609459200000,'Hello from Skype',1);
            INSERT INTO chatitem VALUES(2,'19:abc@thread','live:user2',1609459300000,'Hey there',1);
            INSERT INTO chatitem VALUES(3,'8:live:user1','live:user1',1609459400000,'Call started',3);
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
            .filter(|a| a.subcategory == "Skype Message")
            .collect();
        let calls: Vec<_> = r.iter().filter(|a| a.subcategory == "Skype Call").collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn conversation_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("conversation='19:abc@thread'")));
    }

    #[test]
    fn body_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Hello from Skype")));
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

//! LinkedIn — professional network messaging extraction.
//!
//! ALEAPP reference: `scripts/artifacts/LinkedIn.py`. Source path:
//! `/data/data/com.linkedin.android/databases/messenger-sdk*`.
//!
//! Key tables: `MessagesData`, `ConversationsData`, `ParticipantsData`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.linkedin.android/databases/messenger-sdk"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "MessagesData") {
        return Vec::new();
    }
    read_messages(&conn, path)
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT deliveredAt, status, entityData, conversationUrn, senderUrn \
               FROM MessagesData \
               ORDER BY deliveredAt DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
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
    for (delivered_ms, status, entity_data, conv_urn, sender_urn) in rows.flatten() {
        let status = status.unwrap_or_else(|| "unknown".to_string());
        let entity_data = entity_data.unwrap_or_default();
        let conv_urn = conv_urn.unwrap_or_default();
        let sender_urn = sender_urn.unwrap_or_default();
        let ts = delivered_ms.and_then(unix_ms_to_i64);
        // Try to extract subject/message from entityData JSON
        let (subject, body) = extract_message_text(&entity_data);
        let preview: String = body.chars().take(120).collect();
        let title = format!("LinkedIn {}: {}", sender_urn, preview);
        let mut detail = format!(
            "LinkedIn message sender='{}' conversation='{}' status='{}' body='{}'",
            sender_urn, conv_urn, status, body
        );
        if !subject.is_empty() {
            detail.push_str(&format!(" subject='{}'", subject));
        }
        out.push(build_record(
            ArtifactCategory::Communications,
            "LinkedIn Message",
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

/// Crudely extract subject and message text from the entityData JSON.
///
/// LinkedIn stores protobuf or JSON payloads in `entityData`. For a
/// best-effort decode we look for common field names in the raw string.
/// If the blob is binary protobuf this will simply return empty strings.
fn extract_message_text(raw: &str) -> (String, String) {
    let mut subject = String::new();
    let mut body = String::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(s) = v.get("subject").and_then(|x| x.as_str()) {
            subject = s.to_string();
        }
        if let Some(m) = v.get("message").and_then(|x| x.as_str()) {
            body = m.to_string();
        }
        if body.is_empty() {
            if let Some(t) = v.get("text").and_then(|x| x.as_str()) {
                body = t.to_string();
            }
        }
    } else {
        // Fallback: include the raw string as body if it's short
        if raw.len() < 500
            && raw
                .chars()
                .all(|c| c.is_ascii_graphic() || c.is_whitespace())
        {
            body = raw.to_string();
        }
    }
    (subject, body)
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
            CREATE TABLE MessagesData (
                deliveredAt INTEGER,
                status TEXT,
                entityData TEXT,
                conversationUrn TEXT,
                senderUrn TEXT
            );
            INSERT INTO MessagesData VALUES(1609459200000,'DELIVERED','{"subject":"Job","message":"Are you open to opportunities?"}','urn:conv:1','urn:li:member:100');
            INSERT INTO MessagesData VALUES(1609459300000,'READ','{"message":"Thanks for reaching out"}','urn:conv:1','urn:li:member:200');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_messages() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "LinkedIn Message"));
    }

    #[test]
    fn json_body_extracted() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("body='Are you open to opportunities?'")));
        assert!(r.iter().any(|a| a.detail.contains("subject='Job'")));
    }

    #[test]
    fn sender_urn_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("urn:li:member:100")));
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

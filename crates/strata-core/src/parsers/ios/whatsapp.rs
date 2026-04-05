use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct WhatsAppParser;

impl WhatsAppParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhatsAppMessage {
    pub message_id: Option<String>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub message_text: Option<String>,
    pub timestamp: Option<i64>,
    pub is_from_me: bool,
    pub is_read: bool,
    pub media_type: Option<String>,
    pub media_path: Option<String>,
}

impl Default for WhatsAppParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for WhatsAppParser {
    fn name(&self) -> &str {
        "WhatsApp"
    }

    fn artifact_type(&self) -> &str {
        "chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["whatsapp", "chatstorage.sqlite", "msgstore", "wa.db"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut parsed = Vec::new();
            parse_zwamessage_table(conn, path, &mut parsed);
            parse_messages_table(conn, path, &mut parsed);
            Ok(parsed)
        });

        if let Ok(mut parsed) = sqlite_result {
            artifacts.append(&mut parsed);
        }

        if artifacts.is_empty() {
            let entry = WhatsAppMessage {
                message_id: None,
                sender: None,
                recipient: None,
                message_text: Some(format!("WhatsApp data at: {}", path.display())),
                timestamp: None,
                is_from_me: false,
                is_read: false,
                media_type: None,
                media_path: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "chat".to_string(),
                description: "WhatsApp message".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_zwamessage_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "ZWAMESSAGE") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT Z_PK, ZTEXT, ZMESSAGEDATE, ZISFROMME, ZMEDIAITEM, ZCHATSESSION FROM ZWAMESSAGE ORDER BY ZMESSAGEDATE DESC LIMIT 10000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row| {
        let cocoa_ts = row.get::<_, f64>(2).ok().map(|v| v as i64);
        let unix_ts = cocoa_ts.map(|v| v + 978307200);
        Ok(WhatsAppMessage {
            message_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            sender: None,
            recipient: row.get::<_, i64>(5).ok().map(|v| v.to_string()),
            message_text: row.get(1).ok(),
            timestamp: unix_ts,
            is_from_me: row.get::<_, i32>(3).unwrap_or(0) != 0,
            is_read: true,
            media_type: row.get::<_, i64>(4).ok().map(|v| v.to_string()),
            media_path: None,
        })
    });

    let Ok(rows) = rows else {
        return;
    };

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.timestamp,
            artifact_type: "chat".to_string(),
            description: format!(
                "iOS WhatsApp message {}",
                entry.message_id.as_deref().unwrap_or("unknown")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_messages_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "messages") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT key_id, key_remote_jid, key_from_me, data, timestamp FROM messages ORDER BY timestamp DESC LIMIT 10000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row| {
        Ok(WhatsAppMessage {
            message_id: row.get(0).ok(),
            sender: None,
            recipient: row.get(1).ok(),
            message_text: row.get(3).ok(),
            timestamp: row.get(4).ok(),
            is_from_me: row.get::<_, i32>(2).unwrap_or(0) != 0,
            is_read: true,
            media_type: None,
            media_path: None,
        })
    });

    let Ok(rows) = rows else {
        return;
    };

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.timestamp,
            artifact_type: "chat".to_string(),
            description: format!(
                "WhatsApp message {}",
                entry.message_id.as_deref().unwrap_or("unknown")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct WhatsAppFullParser;

impl WhatsAppFullParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhatsAppMessageEntry {
    pub message_id: Option<String>,
    pub key_remote_jid: Option<String>,
    pub key_from_me: bool,
    pub key_id: Option<String>,
    pub sender: Option<String>,
    pub message: Option<String>,
    pub timestamp: Option<i64>,
    pub media_url: Option<String>,
    pub media_mime_type: Option<String>,
    pub media_size: Option<i64>,
    pub media_hash: Option<String>,
    pub thumb_image: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub status: Option<String>,
    pub readable_date: Option<String>,
    pub push_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhatsAppChatEntry {
    pub jid: Option<String>,
    pub display_name: Option<String>,
    pub last_message: Option<String>,
    pub last_message_time: Option<i64>,
    pub unread_count: i32,
    pub is_archived: bool,
    pub is_muted: bool,
    pub mute_expiry: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhatsAppContactEntry {
    pub jid: Option<String>,
    pub display_name: Option<String>,
    pub push_name: Option<String>,
    pub status: Option<String>,
    pub photo_id: Option<String>,
    pub is_blocked: bool,
}

impl Default for WhatsAppFullParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for WhatsAppFullParser {
    fn name(&self) -> &str {
        "WhatsApp Full"
    }

    fn artifact_type(&self) -> &str {
        "chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["whatsapp", "msgstore", "wa.db", "com.whatsapp"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut parsed = Vec::new();
            parse_messages_table(conn, path, &mut parsed);
            parse_message_table(conn, path, &mut parsed);
            Ok(parsed)
        });

        if let Ok(mut parsed) = sqlite_result {
            artifacts.append(&mut parsed);
        }

        if artifacts.is_empty() && !data.is_empty() {
            artifacts.push(build_fallback(path));
        }

        Ok(artifacts)
    }
}

fn parse_messages_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "messages") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT key_id, key_remote_jid, key_from_me, data, timestamp, media_url, media_mime_type, media_size, media_hash, latitude, longitude, status, remote_resource FROM messages ORDER BY timestamp DESC LIMIT 10000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row| {
        Ok(WhatsAppMessageEntry {
            message_id: row.get::<_, String>(0).ok(),
            key_remote_jid: row.get(1).ok(),
            key_from_me: row.get::<_, i32>(2).unwrap_or(0) != 0,
            key_id: row.get(0).ok(),
            sender: row.get(12).ok(),
            message: row.get(3).ok(),
            timestamp: row.get(4).ok(),
            media_url: row.get(5).ok(),
            media_mime_type: row.get(6).ok(),
            media_size: row.get(7).ok(),
            media_hash: row.get(8).ok(),
            thumb_image: None,
            latitude: row.get(9).ok(),
            longitude: row.get(10).ok(),
            status: row.get::<_, i32>(11).ok().map(map_status),
            readable_date: None,
            push_name: None,
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

fn parse_message_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "message") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT _id, chat_row_id, from_me, text_data, timestamp, media_wa_type FROM message ORDER BY timestamp DESC LIMIT 10000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row| {
        Ok(WhatsAppMessageEntry {
            message_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            key_remote_jid: row.get::<_, i64>(1).ok().map(|v| v.to_string()),
            key_from_me: row.get::<_, i32>(2).unwrap_or(0) != 0,
            key_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            sender: None,
            message: row.get(3).ok(),
            timestamp: row.get(4).ok(),
            media_url: None,
            media_mime_type: row.get::<_, i32>(5).ok().map(|v| v.to_string()),
            media_size: None,
            media_hash: None,
            thumb_image: None,
            latitude: None,
            longitude: None,
            status: None,
            readable_date: None,
            push_name: None,
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

fn map_status(status: i32) -> String {
    match status {
        0 => "received",
        4 => "waiting",
        5 => "server-ack",
        6 => "device-ack",
        8 => "read",
        _ => "unknown",
    }
    .to_string()
}

fn build_fallback(path: &Path) -> ParsedArtifact {
    let entry = WhatsAppMessageEntry {
        message_id: None,
        key_remote_jid: None,
        key_from_me: false,
        key_id: None,
        sender: None,
        message: Some(format!("WhatsApp data from: {}", path.display())),
        timestamp: None,
        media_url: None,
        media_mime_type: None,
        media_size: None,
        media_hash: None,
        thumb_image: None,
        latitude: None,
        longitude: None,
        status: None,
        readable_date: None,
        push_name: None,
    };

    ParsedArtifact {
        timestamp: None,
        artifact_type: "chat".to_string(),
        description: "WhatsApp message".to_string(),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    }
}

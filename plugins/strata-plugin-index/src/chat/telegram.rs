use crate::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct TelegramParser;

impl TelegramParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TelegramMessageEntry {
    pub message_id: Option<i64>,
    pub peer_id: Option<String>,
    pub from_id: Option<String>,
    pub sender_name: Option<String>,
    pub text: Option<String>,
    pub timestamp: Option<i64>,
    pub edit_date: Option<i64>,
    pub media_type: Option<String>,
    pub file_path: Option<String>,
    pub reply_to_msg_id: Option<i64>,
    pub fwd_from: Option<String>,
    pub entities: Vec<String>,
    pub views: Option<i32>,
    pub forwards: Option<i32>,
    pub is_deleted: bool,
    pub is_outgoing: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TelegramChatEntry {
    pub chat_id: Option<String>,
    pub title: Option<String>,
    pub username: Option<String>,
    pub type_: Option<String>,
    pub participants_count: Option<i32>,
    pub date: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TelegramContactEntry {
    pub phone: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub username: Option<String>,
}

impl Default for TelegramParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for TelegramParser {
    fn name(&self) -> &str {
        "Telegram"
    }

    fn artifact_type(&self) -> &str {
        "chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "telegram",
            "Telegram Desktop",
            "tdata",
            "cache4.db",
            "result.json",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        parse_json_export(path, data, &mut artifacts);

        let sqlite_result = with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut parsed = Vec::new();
            parse_messages_table(conn, path, &mut parsed);
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

fn parse_json_export(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    if let Some(messages) = value.get("messages").and_then(|v| v.as_array()) {
        for msg in messages.iter().take(20000) {
            if let Some(artifact) = message_from_json(path, msg) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(array) = value.as_array() {
        for msg in array.iter().take(20000) {
            if let Some(artifact) = message_from_json(path, msg) {
                out.push(artifact);
            }
        }
    }
}

fn message_from_json(path: &Path, value: &serde_json::Value) -> Option<ParsedArtifact> {
    let id = value
        .get("id")
        .and_then(value_to_i64)
        .or_else(|| value.get("message_id").and_then(value_to_i64));
    let text = value
        .get("text")
        .and_then(value_to_text)
        .or_else(|| value.get("message").and_then(value_to_text));
    let sender_name = value
        .get("from")
        .or_else(|| value.get("sender"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let ts = value
        .get("date_unixtime")
        .and_then(value_to_i64)
        .or_else(|| value.get("date").and_then(value_to_i64))
        .or_else(|| value.get("timestamp").and_then(value_to_i64));

    if text.is_none() && id.is_none() {
        return None;
    }

    let entry = TelegramMessageEntry {
        message_id: id,
        peer_id: value.get("peer_id").and_then(value_to_string),
        from_id: value.get("from_id").and_then(value_to_string),
        sender_name,
        text,
        timestamp: ts,
        edit_date: value.get("edit_date").and_then(value_to_i64),
        media_type: value
            .get("media_type")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        file_path: value
            .get("file")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        reply_to_msg_id: value.get("reply_to_message_id").and_then(value_to_i64),
        fwd_from: value
            .get("forwarded_from")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        entities: vec![],
        views: value.get("views").and_then(value_to_i64).map(|v| v as i32),
        forwards: value
            .get("forwards")
            .and_then(value_to_i64)
            .map(|v| v as i32),
        is_deleted: value
            .get("is_deleted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        is_outgoing: value.get("out").and_then(|v| v.as_bool()).unwrap_or(false),
    };

    Some(ParsedArtifact {
        timestamp: entry.timestamp,
        artifact_type: "chat".to_string(),
        description: format!(
            "Telegram export message {}",
            entry
                .message_id
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    })
}

fn parse_messages_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "messages") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT mid, uid, date, data, out, replydata, views, forwards FROM messages ORDER BY date DESC LIMIT 10000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row: &rusqlite::Row| {
        Ok(TelegramMessageEntry {
            message_id: row.get(0).ok(),
            peer_id: row.get::<_, i64>(1).ok().map(|v| v.to_string()),
            from_id: None,
            sender_name: None,
            text: row.get(3).ok(),
            timestamp: row.get(2).ok(),
            edit_date: None,
            media_type: None,
            file_path: None,
            reply_to_msg_id: row.get(5).ok(),
            fwd_from: None,
            entities: vec![],
            views: row.get(6).ok(),
            forwards: row.get(7).ok(),
            is_deleted: false,
            is_outgoing: row.get::<_, i32>(4).unwrap_or(0) != 0,
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
                "Telegram message {}",
                entry
                    .message_id
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn value_to_text(value: &serde_json::Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.to_string());
    }
    if let Some(items) = value.as_array() {
        let mut text = String::new();
        for item in items {
            if let Some(segment) = item.as_str() {
                if !text.is_empty() {
                    text.push(' ');
                }
                text.push_str(segment);
            } else if let Some(obj_text) = item.get("text").and_then(|v| v.as_str()) {
                if !text.is_empty() {
                    text.push(' ');
                }
                text.push_str(obj_text);
            }
        }
        if !text.is_empty() {
            return Some(text);
        }
    }
    None
}

fn value_to_i64(value: &serde_json::Value) -> Option<i64> {
    if let Some(v) = value.as_i64() {
        return Some(v);
    }
    if let Some(v) = value.as_u64() {
        return i64::try_from(v).ok();
    }
    if let Some(v) = value.as_str() {
        return v.parse::<i64>().ok();
    }
    None
}

fn value_to_string(value: &serde_json::Value) -> Option<String> {
    if let Some(v) = value.as_str() {
        return Some(v.to_string());
    }
    value_to_i64(value).map(|v| v.to_string())
}

fn build_fallback(path: &Path) -> ParsedArtifact {
    let entry = TelegramMessageEntry {
        message_id: None,
        peer_id: None,
        from_id: None,
        sender_name: None,
        text: Some(format!("Telegram data from: {}", path.display())),
        timestamp: None,
        edit_date: None,
        media_type: None,
        file_path: None,
        reply_to_msg_id: None,
        fwd_from: None,
        entities: vec![],
        views: None,
        forwards: None,
        is_deleted: false,
        is_outgoing: false,
    };

    ParsedArtifact {
        timestamp: None,
        artifact_type: "chat".to_string(),
        description: "Telegram message".to_string(),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    }
}

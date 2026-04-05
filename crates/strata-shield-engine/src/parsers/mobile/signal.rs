use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct SignalParser;

impl SignalParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalMessageEntry {
    pub message_id: Option<String>,
    pub conversation_id: Option<String>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub body: Option<String>,
    pub timestamp: Option<i64>,
    pub received_timestamp: Option<i64>,
    pub is_read: bool,
    pub is_delivered: bool,
    pub is_sent: bool,
    pub is_successful: bool,
    pub attachments: Vec<String>,
    pub mentions: Vec<String>,
    pub quote: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalContactEntry {
    pub uuid: Option<String>,
    pub phone_number: Option<String>,
    pub name: Option<String>,
    pub avatar_path: Option<String>,
    pub color: Option<String>,
    pub is_blocked: bool,
    pub mute_until: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalGroupEntry {
    pub group_id: Option<String>,
    pub title: Option<String>,
    pub members: Vec<String>,
    pub avatar_path: Option<String>,
    pub timestamp: Option<i64>,
    pub is_archived: bool,
}

impl Default for SignalParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SignalParser {
    fn name(&self) -> &str {
        "Signal"
    }

    fn artifact_type(&self) -> &str {
        "chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "signal",
            "org.thoughtcrime.securesms",
            "signal.db",
            "db.sqlite",
            "signalbackup",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut parsed = Vec::new();
            parse_message_table(conn, path, &mut parsed);
            parse_sms_table(conn, path, &mut parsed);
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

fn parse_message_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "message") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT _id, thread_id, body, date_sent, date_received, type, read FROM message ORDER BY date_sent DESC LIMIT 5000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row| {
        let msg_type = row.get::<_, i32>(5).unwrap_or(0);
        Ok(SignalMessageEntry {
            message_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            conversation_id: row.get::<_, i64>(1).ok().map(|v| v.to_string()),
            sender: None,
            recipient: None,
            body: row.get(2).ok(),
            timestamp: row.get(3).ok(),
            received_timestamp: row.get(4).ok(),
            is_read: row.get::<_, i32>(6).unwrap_or(0) != 0,
            is_delivered: matches!(msg_type, 4 | 5),
            is_sent: matches!(msg_type, 2 | 3 | 4 | 5),
            is_successful: matches!(msg_type, 2 | 4 | 5),
            attachments: vec![],
            mentions: vec![],
            quote: None,
        })
    });

    let Ok(rows) = rows else {
        return;
    };

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.timestamp.or(entry.received_timestamp),
            artifact_type: "chat".to_string(),
            description: format!(
                "Signal message {}",
                entry.message_id.as_deref().unwrap_or("unknown")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_sms_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "sms") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT _id, thread_id, address, body, date, read, type FROM sms ORDER BY date DESC LIMIT 5000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row| {
        let msg_type = row.get::<_, i32>(6).unwrap_or(0);
        Ok(SignalMessageEntry {
            message_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            conversation_id: row.get::<_, i64>(1).ok().map(|v| v.to_string()),
            sender: row.get(2).ok(),
            recipient: None,
            body: row.get(3).ok(),
            timestamp: row.get(4).ok(),
            received_timestamp: None,
            is_read: row.get::<_, i32>(5).unwrap_or(0) != 0,
            is_delivered: msg_type == 2,
            is_sent: msg_type == 2,
            is_successful: msg_type == 2,
            attachments: vec![],
            mentions: vec![],
            quote: None,
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
                "Signal SMS {}",
                entry.message_id.as_deref().unwrap_or("unknown")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn build_fallback(path: &Path) -> ParsedArtifact {
    let entry = SignalMessageEntry {
        message_id: None,
        conversation_id: None,
        sender: None,
        recipient: None,
        body: Some(format!("Signal data from: {}", path.display())),
        timestamp: None,
        received_timestamp: None,
        is_read: false,
        is_delivered: false,
        is_sent: false,
        is_successful: false,
        attachments: vec![],
        mentions: vec![],
        quote: None,
    };

    ParsedArtifact {
        timestamp: None,
        artifact_type: "chat".to_string(),
        description: "Signal message".to_string(),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    }
}

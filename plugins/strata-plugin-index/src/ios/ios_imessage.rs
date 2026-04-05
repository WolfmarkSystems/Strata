use crate::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct IosImessageParser;

impl IosImessageParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IosImessageEntry {
    pub message_id: Option<String>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub message_text: Option<String>,
    pub timestamp: Option<i64>,
    pub is_read: bool,
    pub is_from_me: bool,
    pub service: Option<String>,
    pub attachment_count: i32,
}

impl Default for IosImessageParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosImessageParser {
    fn name(&self) -> &str {
        "iOS iMessage"
    }

    fn artifact_type(&self) -> &str {
        "chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["imessage", "sms.db", "chat.db"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut parsed = Vec::new();
            parse_message_table(conn, path, &mut parsed);
            Ok(parsed)
        });

        if let Ok(mut parsed) = sqlite_result {
            artifacts.append(&mut parsed);
        }

        if artifacts.is_empty() {
            let entry = IosImessageEntry {
                message_id: None,
                sender: None,
                recipient: None,
                message_text: Some(format!("iOS iMessage data at: {}", path.display())),
                timestamp: None,
                is_read: false,
                is_from_me: false,
                service: Some("iMessage".to_string()),
                attachment_count: 0,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "chat".to_string(),
                description: "iOS iMessage conversation".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_message_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "message") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT ROWID, text, date, is_read, is_from_me, service, cache_has_attachments FROM message ORDER BY date DESC LIMIT 10000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row: &rusqlite::Row| {
        let apple_epoch: Option<i64> = row.get(2).ok();
        let unix_ts = apple_epoch.map(normalize_ios_message_time);
        Ok(IosImessageEntry {
            message_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            sender: None,
            recipient: None,
            message_text: row.get(1).ok(),
            timestamp: unix_ts,
            is_read: row.get::<_, i32>(3).unwrap_or(0) != 0,
            is_from_me: row.get::<_, i32>(4).unwrap_or(0) != 0,
            service: row.get(5).ok(),
            attachment_count: row.get::<_, i32>(6).unwrap_or(0),
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
                "iMessage {}",
                entry.message_id.as_deref().unwrap_or("unknown")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn normalize_ios_message_time(value: i64) -> i64 {
    if value > 1_000_000_000_000 {
        (value / 1_000_000_000) + 978_307_200
    } else {
        value + 978_307_200
    }
}

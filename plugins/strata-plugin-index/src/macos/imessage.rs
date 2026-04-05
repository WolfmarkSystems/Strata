use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct ImessageParser;

impl ImessageParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImessageEntry {
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

impl Default for ImessageParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for ImessageParser {
    fn name(&self) -> &str {
        "iMessage"
    }

    fn artifact_type(&self) -> &str {
        "chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["imessage", "chat.db", "messages"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        use crate::sqlite_utils::{table_exists, with_sqlite_connection};

        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut entries = Vec::new();
            if table_exists(conn, "message") {
                let mut stmt = conn
                    .prepare(
                        "SELECT 
                        message.guid, 
                        handle.id, 
                        message.text, 
                        message.date, 
                        message.is_read, 
                        message.is_from_me,
                        message.service
                     FROM message 
                     LEFT JOIN handle ON message.handle_id = handle.rowid 
                     LIMIT 5000",
                    )
                    .map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row: &rusqlite::Row| {
                        Ok(ImessageEntry {
                            message_id: row.get(0).ok(),
                            sender: row.get(1).ok(),
                            recipient: None,
                            message_text: row.get(2).ok(),
                            timestamp: row
                                .get::<_, i64>(3)
                                .ok()
                                .map(|d| (d / 1_000_000_000) + 978307200),
                            is_read: row.get::<_, i64>(4).unwrap_or(0) != 0,
                            is_from_me: row.get::<_, i64>(5).unwrap_or(0) != 0,
                            service: row.get(6).ok(),
                            attachment_count: 0,
                        })
                    })
                    .map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: row.timestamp,
                        artifact_type: "chat".to_string(),
                        description: format!(
                            "iMessage: {} -> {}",
                            row.sender.as_deref().unwrap_or("Me"),
                            row.message_text.as_deref().unwrap_or("")
                        ),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(row).unwrap_or_default(),
                    });
                }
            }
            Ok(entries)
        });

        if let Ok(mut entries) = sqlite_result {
            artifacts.append(&mut entries);
        }

        Ok(artifacts)
    }
}

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Facebook Messenger Parser
///
/// Parses:
///   - Mobile: threads_db2 / msys_database (SQLite) — iOS/Android
///   - Desktop: LevelDB databases (partial — metadata extraction)
///   - Data Download: JSON export from Facebook
///
/// Forensic value: One of the most common communication platforms in criminal
/// investigations (fraud, trafficking, threats, CSAM). Messages, calls,
/// contacts, and media attachments.
pub struct FacebookMessengerParser;

impl Default for FacebookMessengerParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FacebookMessengerParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessengerMessage {
    pub thread_key: Option<String>,
    pub sender_name: Option<String>,
    pub sender_id: Option<String>,
    pub message_text: Option<String>,
    pub timestamp_ms: Option<i64>,
    pub message_type: Option<String>,
    pub has_attachment: bool,
    pub attachment_type: Option<String>,
    pub is_unsent: bool,
    pub thread_name: Option<String>,
    pub reaction: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessengerThread {
    pub thread_key: String,
    pub thread_name: Option<String>,
    pub participant_count: Option<i32>,
    pub last_activity_timestamp: Option<i64>,
    pub is_group: bool,
    pub message_count: Option<i32>,
}

impl ArtifactParser for FacebookMessengerParser {
    fn name(&self) -> &str {
        "Facebook Messenger Parser"
    }

    fn artifact_type(&self) -> &str {
        "chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "threads_db2",
            "threads_db2-journal",
            "msys_database",
            "messenger_*.json",
            "message_*.json",
            "messages.json",
            "lightspeed-*.db",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .to_lowercase();

        if filename.ends_with(".json") {
            self.parse_json_export(path, data)
        } else {
            self.parse_sqlite_db(path, data)
        }
    }
}

impl FacebookMessengerParser {
    fn parse_sqlite_db(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();

            // threads_db2 schema (Android/iOS Messenger)
            if table_exists(conn, "messages") {
                let mut stmt = conn
                    .prepare(
                        "SELECT
                            m.thread_key,
                            m.sender_id,
                            m.text,
                            m.timestamp_ms,
                            m.msg_type,
                            m.has_attachment,
                            m.attachment_type,
                            t.name
                         FROM messages m
                         LEFT JOIN threads t ON m.thread_key = t.thread_key
                         WHERE m.timestamp_ms IS NOT NULL
                         ORDER BY m.timestamp_ms DESC
                         LIMIT 10000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok(MessengerMessage {
                            thread_key: row.get(0).ok(),
                            sender_name: None,
                            sender_id: row.get(1).ok(),
                            message_text: row.get(2).ok(),
                            timestamp_ms: row.get(3).ok(),
                            message_type: row.get::<_, String>(4).ok(),
                            has_attachment: row.get::<_, i32>(5).unwrap_or(0) != 0,
                            attachment_type: row.get(6).ok(),
                            is_unsent: false,
                            thread_name: row.get(7).ok(),
                            reaction: None,
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    let ts_epoch = row.timestamp_ms.map(|ms| ms / 1000);
                    let sender = row
                        .sender_id
                        .as_deref()
                        .or(row.sender_name.as_deref())
                        .unwrap_or("unknown");
                    let preview = row
                        .message_text
                        .as_deref()
                        .map(|t| {
                            if t.len() > 100 {
                                format!("{}...", &t[..100])
                            } else {
                                t.to_string()
                            }
                        })
                        .unwrap_or_else(|| "[no text]".to_string());

                    entries.push(ParsedArtifact {
                        timestamp: ts_epoch,
                        artifact_type: "chat_message".to_string(),
                        description: format!(
                            "Messenger: {} -> {} — {}",
                            sender,
                            row.thread_name.as_deref().unwrap_or("DM"),
                            preview,
                        ),
                        source_path: source.clone(),
                        json_data: serde_json::to_value(&row).unwrap_or_default(),
                    });
                }
            }

            // Also try msys_database schema (newer Messenger versions)
            if (table_exists(conn, "secure_message_info") || table_exists(conn, "thread_info"))
                && table_exists(conn, "thread_info")
            {
                let mut stmt = conn
                    .prepare(
                        "SELECT
                            thread_key,
                            name,
                            participant_count,
                            last_activity_timestamp_ms
                         FROM thread_info
                         ORDER BY last_activity_timestamp_ms DESC
                         LIMIT 5000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok(MessengerThread {
                            thread_key: row.get::<_, String>(0).unwrap_or_default(),
                            thread_name: row.get(1).ok(),
                            participant_count: row.get(2).ok(),
                            last_activity_timestamp: row.get::<_, i64>(3).ok().map(|ms| ms / 1000),
                            is_group: row.get::<_, i32>(2).unwrap_or(0) > 2,
                            message_count: None,
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: row.last_activity_timestamp,
                        artifact_type: "chat_thread".to_string(),
                        description: format!(
                            "Messenger Thread: {} ({} participants){}",
                            row.thread_name.as_deref().unwrap_or("unnamed"),
                            row.participant_count.unwrap_or(0),
                            if row.is_group { " [GROUP]" } else { "" },
                        ),
                        source_path: source.clone(),
                        json_data: serde_json::to_value(&row).unwrap_or_default(),
                    });
                }
            }

            Ok(entries)
        });

        if let Ok(mut entries) = sqlite_result {
            artifacts.append(&mut entries);
        }

        if artifacts.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "chat".to_string(),
                description: format!(
                    "Facebook Messenger DB: {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "note": "Facebook Messenger database detected.",
                }),
            });
        }

        Ok(artifacts)
    }

    fn parse_json_export(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
            return Ok(artifacts);
        };

        // Facebook data download JSON format
        if let Some(messages) = json.get("messages").and_then(|m| m.as_array()) {
            let thread_name = json
                .get("title")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");

            for msg in messages.iter().take(10000) {
                let sender = msg
                    .get("sender_name")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
                let ts_ms = msg.get("timestamp_ms").and_then(|t| t.as_i64());
                let has_photos = msg.get("photos").is_some();
                let has_videos = msg.get("videos").is_some();
                let has_audio = msg.get("audio_files").is_some();

                let preview = if content.len() > 100 {
                    format!("{}...", &content[..100])
                } else {
                    content.to_string()
                };

                let mut desc = format!("Messenger: {} -> {} — {}", sender, thread_name, preview);
                if has_photos {
                    desc.push_str(" [PHOTO]");
                }
                if has_videos {
                    desc.push_str(" [VIDEO]");
                }
                if has_audio {
                    desc.push_str(" [AUDIO]");
                }

                artifacts.push(ParsedArtifact {
                    timestamp: ts_ms.map(|ms| ms / 1000),
                    artifact_type: "chat_message".to_string(),
                    description: desc,
                    source_path: source.clone(),
                    json_data: serde_json::json!({
                        "sender_name": sender,
                        "thread_name": thread_name,
                        "message_text": content,
                        "timestamp_ms": ts_ms,
                        "has_photo": has_photos,
                        "has_video": has_videos,
                        "has_audio": has_audio,
                    }),
                });
            }
        }

        Ok(artifacts)
    }
}

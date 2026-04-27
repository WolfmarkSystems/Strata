use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Windows Push Notification Database parser
/// Path: %LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db
///
/// Contains notification content (toasts, badges, tiles) from all Windows
/// apps. Notifications persist even after dismissal. Available Windows 10+.
pub struct WindowsNotificationsParser;

impl Default for WindowsNotificationsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsNotificationsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NotificationEntry {
    pub handler_id: Option<String>,
    pub notification_type: Option<String>,
    pub payload: Option<String>,
    pub payload_type: Option<String>,
    pub tag: Option<String>,
    pub group_name: Option<String>,
    pub arrival_time: Option<i64>,
    pub expiry_time: Option<i64>,
    pub boot_id: Option<i64>,
    pub activity_id: Option<String>,
    pub extracted_text: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NotificationHandlerEntry {
    pub primary_id: Option<String>,
    pub handler_type: Option<String>,
    pub display_name: Option<String>,
    pub created_time: Option<i64>,
    pub modified_time: Option<i64>,
}

impl ArtifactParser for WindowsNotificationsParser {
    fn name(&self) -> &str {
        "Windows Notification Database Parser"
    }

    fn artifact_type(&self) -> &str {
        "notification"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["wpndatabase.db", "WpnDatabase.db", "WPNDATABASE.DB"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();

            // Parse Notification table
            if table_exists(conn, "Notification") {
                let mut stmt = conn
                    .prepare(
                        "SELECT
                            N.HandlerId,
                            N.Type,
                            N.Payload,
                            N.PayloadType,
                            N.Tag,
                            N.\"Group\",
                            N.ArrivalTime,
                            N.ExpiryTime,
                            N.BootId,
                            N.ActivityId,
                            NH.PrimaryId
                         FROM Notification N
                         LEFT JOIN NotificationHandler NH ON N.HandlerId = NH.RecordId
                         ORDER BY N.ArrivalTime DESC
                         LIMIT 10000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        let payload: Option<String> = row.get(2).ok();
                        let extracted = payload.as_deref().map(extract_notification_text);

                        Ok(NotificationEntry {
                            handler_id: row.get::<_, String>(10).ok().or_else(|| {
                                row.get::<_, i64>(0)
                                    .ok()
                                    .map(|id| format!("handler_{}", id))
                            }),
                            notification_type: row.get::<_, String>(1).ok().or_else(|| {
                                row.get::<_, i32>(1)
                                    .ok()
                                    .map(|t| notification_type_name(t).to_string())
                            }),
                            payload,
                            payload_type: row.get(3).ok(),
                            tag: row.get(4).ok(),
                            group_name: row.get(5).ok(),
                            arrival_time: row.get(6).ok(),
                            expiry_time: row.get(7).ok(),
                            boot_id: row.get(8).ok(),
                            activity_id: row.get(9).ok(),
                            extracted_text: extracted,
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    let handler = row.handler_id.as_deref().unwrap_or("unknown");
                    let ntype = row.notification_type.as_deref().unwrap_or("toast");

                    let mut desc = format!("Notification: {} [{}]", handler, ntype);
                    if let Some(ref text) = row.extracted_text {
                        if !text.is_empty() {
                            let preview = if text.len() > 120 {
                                format!("{}...", &text[..120])
                            } else {
                                text.clone()
                            };
                            desc.push_str(&format!(" — {}", preview));
                        }
                    }

                    entries.push(ParsedArtifact {
                        timestamp: row.arrival_time,
                        artifact_type: "notification".to_string(),
                        description: desc,
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(&row).unwrap_or_default(),
                    });
                }
            }

            // Parse NotificationHandler for app registration
            if table_exists(conn, "NotificationHandler") {
                let mut stmt = conn
                    .prepare(
                        "SELECT
                            PrimaryId,
                            HandlerType,
                            DisplayName,
                            CreatedTime,
                            ModifiedTime
                         FROM NotificationHandler
                         ORDER BY ModifiedTime DESC
                         LIMIT 5000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok(NotificationHandlerEntry {
                            primary_id: row.get(0).ok(),
                            handler_type: row.get::<_, String>(1).ok().or_else(|| {
                                row.get::<_, i32>(1).ok().map(|t| format!("type_{}", t))
                            }),
                            display_name: row.get(2).ok(),
                            created_time: row.get(3).ok(),
                            modified_time: row.get(4).ok(),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    let name = row
                        .display_name
                        .as_deref()
                        .or(row.primary_id.as_deref())
                        .unwrap_or("unknown");

                    entries.push(ParsedArtifact {
                        timestamp: row.modified_time,
                        artifact_type: "notification_handler".to_string(),
                        description: format!(
                            "Notification Handler: {} ({})",
                            name,
                            row.handler_type.as_deref().unwrap_or("unknown")
                        ),
                        source_path: path.to_string_lossy().to_string(),
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
                artifact_type: "notification".to_string(),
                description: format!(
                    "WPN Database: {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "note": "Windows Push Notification database detected."
                }),
            });
        }

        Ok(artifacts)
    }
}

fn notification_type_name(code: i32) -> &'static str {
    match code {
        0 => "toast",
        1 => "badge",
        2 => "tile",
        3 => "raw",
        _ => "unknown",
    }
}

/// Extract readable text from XML notification payload
fn extract_notification_text(payload: &str) -> String {
    let mut texts = Vec::new();
    // Simple XML text extraction without a full XML parser
    let mut remaining = payload;
    while let Some(start) = remaining.find("<text") {
        if let Some(close_tag) = remaining[start..].find('>') {
            let content_start = start + close_tag + 1;
            if let Some(end) = remaining[content_start..].find("</text>") {
                let text = &remaining[content_start..content_start + end];
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    texts.push(trimmed.to_string());
                }
                remaining = &remaining[content_start + end..];
            } else {
                break;
            }
        } else {
            break;
        }
    }
    texts.join(" | ")
}

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Windows ActivitiesCache.db parser (Windows Timeline)
/// Path: %LOCALAPPDATA%\ConnectedDevicesPlatform\<user>\ActivitiesCache.db
///
/// Records application usage, file access, web browsing, and clipboard
/// across devices linked to a Microsoft account. Available Windows 10 1803+.
pub struct ActivitiesCacheParser;

impl Default for ActivitiesCacheParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivitiesCacheParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub app_id: Option<String>,
    pub activity_type: Option<i32>,
    pub activity_status: Option<i32>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub last_modified_time: Option<i64>,
    pub expiration_time: Option<i64>,
    pub payload: Option<String>,
    pub display_text: Option<String>,
    pub description_text: Option<String>,
    pub app_activity_id: Option<String>,
    pub content_uri: Option<String>,
    pub platform_device_id: Option<String>,
    pub duration: Option<i64>,
    pub is_local_only: Option<bool>,
    pub etag: Option<i64>,
    pub group_app_id: Option<String>,
    pub enterprise_id: Option<String>,
    pub original_payload: Option<String>,
}

/// Map Windows activity type code to human-readable description
fn activity_type_name(code: i32) -> &'static str {
    match code {
        5 => "App/URI Launch",
        6 => "App/URI in Focus",
        10 => "Clipboard",
        16 => "Copy/Paste",
        _ => "Unknown",
    }
}

/// Map activity status to description
fn activity_status_name(code: i32) -> &'static str {
    match code {
        1 => "Active",
        2 => "Updated",
        3 => "Deleted",
        4 => "Ignored",
        _ => "Unknown",
    }
}

impl ArtifactParser for ActivitiesCacheParser {
    fn name(&self) -> &str {
        "Windows ActivitiesCache Parser"
    }

    fn artifact_type(&self) -> &str {
        "user_activity"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["ActivitiesCache.db", "activitiescache.db"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();

            // Parse Activity table
            if table_exists(conn, "Activity") {
                let mut stmt = conn
                    .prepare(
                        "SELECT
                            AppId,
                            ActivityType,
                            ActivityStatus,
                            StartTime,
                            EndTime,
                            LastModifiedTime,
                            ExpirationTime,
                            Payload,
                            AppActivityId,
                            PlatformDeviceId,
                            EndTime - StartTime,
                            IsLocalOnly,
                            ETag,
                            GroupAppId,
                            EnterpriseId,
                            OriginalPayload
                         FROM Activity
                         WHERE StartTime IS NOT NULL
                         ORDER BY StartTime DESC
                         LIMIT 10000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        // Extract display text from JSON payload
                        let payload_str: Option<String> = row.get(7).ok();
                        let (display_text, description_text, content_uri) =
                            extract_payload_fields(payload_str.as_deref());

                        Ok(ActivityEntry {
                            app_id: row.get(0).ok(),
                            activity_type: row.get(1).ok(),
                            activity_status: row.get(2).ok(),
                            start_time: row.get(3).ok(),
                            end_time: row.get(4).ok(),
                            last_modified_time: row.get(5).ok(),
                            expiration_time: row.get(6).ok(),
                            payload: payload_str,
                            display_text,
                            description_text,
                            app_activity_id: row.get(8).ok(),
                            content_uri,
                            platform_device_id: row.get(9).ok(),
                            duration: row.get::<_, i64>(10).ok().filter(|&d| d > 0),
                            is_local_only: row.get::<_, bool>(11).ok(),
                            etag: row.get(12).ok(),
                            group_app_id: row.get(13).ok(),
                            enterprise_id: row.get(14).ok(),
                            original_payload: row.get(15).ok(),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    let type_name = row
                        .activity_type
                        .map(activity_type_name)
                        .unwrap_or("Unknown");
                    let status_name = row
                        .activity_status
                        .map(activity_status_name)
                        .unwrap_or("Unknown");

                    let app_display = row.app_id.as_deref().unwrap_or("unknown");
                    let mut desc = format!(
                        "Timeline: {} [{}] ({})",
                        app_display, type_name, status_name
                    );
                    if let Some(ref text) = row.display_text {
                        if !text.is_empty() {
                            desc.push_str(&format!(" — {}", text));
                        }
                    }
                    if let Some(dur) = row.duration {
                        desc.push_str(&format!(" [{}s]", dur));
                    }

                    entries.push(ParsedArtifact {
                        timestamp: row.start_time,
                        artifact_type: "user_activity".to_string(),
                        description: desc,
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(&row).unwrap_or_default(),
                    });
                }
            }

            // Parse ActivityOperation table for sync events
            if table_exists(conn, "ActivityOperation") {
                let mut stmt = conn
                    .prepare(
                        "SELECT
                            OperationType,
                            AppId,
                            ActivityType,
                            CreatedTime,
                            ExpirationTime,
                            Payload
                         FROM ActivityOperation
                         WHERE CreatedTime IS NOT NULL
                         ORDER BY CreatedTime DESC
                         LIMIT 5000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, i32>(0).unwrap_or(0),
                            row.get::<_, String>(1).unwrap_or_default(),
                            row.get::<_, i32>(2).unwrap_or(0),
                            row.get::<_, i64>(3).ok(),
                            row.get::<_, i64>(4).ok(),
                            row.get::<_, String>(5).ok(),
                        ))
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    let op_type = match row.0 {
                        1 => "Created",
                        2 => "Updated",
                        3 => "Deleted",
                        _ => "Unknown",
                    };

                    entries.push(ParsedArtifact {
                        timestamp: row.3,
                        artifact_type: "user_activity_sync".to_string(),
                        description: format!(
                            "Timeline Sync: {} {} [{}]",
                            op_type,
                            row.1,
                            activity_type_name(row.2)
                        ),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::json!({
                            "operation_type": op_type,
                            "app_id": row.1,
                            "activity_type": activity_type_name(row.2),
                            "created_time": row.3,
                            "expiration_time": row.4,
                            "payload_preview": row.5.as_deref().map(|s| &s[..s.len().min(200)]),
                        }),
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
                artifact_type: "user_activity".to_string(),
                description: format!(
                    "ActivitiesCache.db: {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "note": "Windows Timeline database detected but could not parse contents."
                }),
            });
        }

        Ok(artifacts)
    }
}

fn extract_payload_fields(
    payload: Option<&str>,
) -> (Option<String>, Option<String>, Option<String>) {
    let Some(payload) = payload else {
        return (None, None, None);
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) else {
        return (None, None, None);
    };

    let display_text = v
        .get("displayText")
        .and_then(|v| v.as_str())
        .map(String::from);
    let description_text = v
        .get("description")
        .and_then(|v| v.as_str())
        .map(String::from);
    let content_uri = v
        .get("contentUri")
        .and_then(|v| v.as_str())
        .map(String::from);

    (display_text, description_text, content_uri)
}

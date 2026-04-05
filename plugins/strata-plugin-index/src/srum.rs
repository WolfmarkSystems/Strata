use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct SrumParser;

impl Default for SrumParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SrumParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SrumEntry {
    pub app_id: String,
    pub app_name: Option<String>,
    pub user_id: String,
    pub session_id: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub foreground_time: Option<i64>,
    pub background_time: Option<i64>,
    pub usage_count: i32,
}

impl ArtifactParser for SrumParser {
    fn name(&self) -> &str {
        "Windows SRUM Parser"
    }

    fn artifact_type(&self) -> &str {
        "srum"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["SRUDB.dat", "srumdb.dat", "SRUMDB.DAT"]
    }

    fn parse_file(&self, path: &Path, _data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if let Ok(conn) = Connection::open(path) {
            let tables = [
                ("AppRuntime", "app_id, app_name, user_id, session_id, start_time, end_time, foreground_time, background_time, usage_count"),
                ("AppTimeline", "app_id, app_name, user_id, session_id, start_time, end_time"),
                ("NetworkUsage", "app_id, user_id, session_id, bytes_sent, bytes_received, connect_time"),
            ];

            for (table, columns) in tables.iter() {
                let query = format!("SELECT {} FROM {} LIMIT 500", columns, table);

                if let Ok(mut stmt) = conn.prepare(&query) {
                    let rows = stmt.query_map([], |row: &rusqlite::Row| {
                        let entry = SrumEntry {
                            app_id: row.get::<_, String>(0).unwrap_or_default(),
                            app_name: row.get(1).ok(),
                            user_id: row.get::<_, String>(2).unwrap_or_default(),
                            session_id: row.get(3).ok(),
                            start_time: row.get::<_, i64>(4).ok(),
                            end_time: row.get::<_, i64>(5).ok(),
                            foreground_time: row.get::<_, i64>(6).ok(),
                            background_time: row.get::<_, i64>(7).ok(),
                            usage_count: row.get::<_, i32>(8).unwrap_or(0),
                        };
                        Ok(entry)
                    });

                    if let Ok(rows) = rows {
                        for entry in rows.flatten() {
                            if !entry.app_id.is_empty() {
                                artifacts.push(ParsedArtifact {
                                    timestamp: entry.start_time,
                                    artifact_type: "srum_entry".to_string(),
                                    description: format!(
                                        "SRUM: {} ({})",
                                        entry.app_name.as_deref().unwrap_or(&entry.app_id),
                                        entry.user_id
                                    ),
                                    source_path: path.to_string_lossy().to_string(),
                                    json_data: serde_json::to_value(entry).unwrap_or_default(),
                                });
                            }
                        }
                    }
                }
            }
        }

        if artifacts.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "srum".to_string(),
                description: format!(
                    "SRUM database: {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "note": "SRUM database file. Full parsing requires Windows ESE database format."
                }),
            });
        }

        Ok(artifacts)
    }
}

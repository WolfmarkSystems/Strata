use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{with_sqlite_connection, table_exists};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosScreentimeParser;

impl MacosScreentimeParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScreentimeEvent {
    pub bundle_id: String,
    pub total_time_ms: i64,
    pub date: Option<i64>,
}

impl Default for MacosScreentimeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosScreentimeParser {
    fn name(&self) -> &str {
        "macOS Screen Time"
    }

    fn artifact_type(&self) -> &str {
        "user_activity"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["RMAdminStore.sqlite", "screentime"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();
            if table_exists(conn, "ZUSAGEBLOCK") {
                 let mut stmt = conn.prepare(
                    "SELECT ZBUNDLEID, ZTOTALTIME, ZLASTMODIFIEDDATE FROM ZUSAGEBLOCK LIMIT 5000"
                ).map_err(|e| ParserError::Database(e.to_string()))?;
                
                let rows = stmt.query_map([], |row| {
                    Ok(ScreentimeEvent {
                        bundle_id: row.get::<_, String>(0).unwrap_or_else(|_| "unknown".to_string()),
                        total_time_ms: row.get::<_, f64>(1).map(|t| (t * 1000.0) as i64).unwrap_or(0),
                        date: row.get::<_, f64>(2).ok().map(|d| d as i64 + 978307200),
                    })
                }).map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                      entries.push(ParsedArtifact {
                        timestamp: row.date,
                        artifact_type: "user_activity".to_string(),
                        description: format!("Screen Time: {} used for {}s", row.bundle_id, row.total_time_ms / 1000),
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

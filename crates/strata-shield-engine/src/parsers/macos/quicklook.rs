use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{with_sqlite_connection, table_exists};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosQuickLookParser;

impl MacosQuickLookParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuickLookEntry {
    pub file_name: String,
    pub last_used: Option<i64>,
    pub hit_count: Option<i64>,
}

impl Default for MacosQuickLookParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosQuickLookParser {
    fn name(&self) -> &str {
        "macOS QuickLook Cache"
    }

    fn artifact_type(&self) -> &str {
        "user_activity"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["com.apple.QuickLook.thumbnailcache", "index.sqlite", "thumbnails.data"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.contains("index.sqlite") {
             let sqlite_result = with_sqlite_connection(path, data, |conn| {
                let mut entries = Vec::new();
                if table_exists(conn, "files") {
                     let mut stmt = conn.prepare(
                        "SELECT file_name, last_used, hit_count FROM files WHERE file_name IS NOT NULL LIMIT 1000"
                    ).map_err(|e| ParserError::Database(e.to_string()))?;
                    
                    let rows = stmt.query_map([], |row| {
                        Ok(QuickLookEntry {
                            file_name: row.get(0).ok().unwrap_or_else(|| "unknown".to_string()),
                            last_used: row.get::<_, f64>(1).ok().map(|d| (d + 978307200.0) as i64),
                            hit_count: row.get(2).ok(),
                        })
                    }).map_err(|e| ParserError::Database(e.to_string()))?;

                    for row in rows.flatten() {
                         entries.push(ParsedArtifact {
                            timestamp: row.last_used,
                            artifact_type: "user_activity".to_string(),
                            description: format!("QuickLook Preview: {}", row.file_name),
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
        }

        Ok(artifacts)
    }
}

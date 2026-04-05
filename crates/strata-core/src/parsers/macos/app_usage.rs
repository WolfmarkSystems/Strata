use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosAppUsageParser;

impl MacosAppUsageParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppUsageEntry {
    pub bundle_id: String,
    pub last_used: Option<i64>,
    pub count: Option<i64>,
}

impl Default for MacosAppUsageParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosAppUsageParser {
    fn name(&self) -> &str {
        "macOS App Usage"
    }

    fn artifact_type(&self) -> &str {
        "application_usage"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["app_usage.sqlite", "com.apple.appusage.plist"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.contains(".sqlite") {
            let sqlite_result = with_sqlite_connection(path, data, |conn| {
                let mut entries = Vec::new();
                if table_exists(conn, "ZAPPUSAGE") {
                    let mut stmt = conn.prepare(
                        "SELECT ZBUNDLEID, ZLASTUSEDDATE, ZUSAGECOUNT FROM ZAPPUSAGE WHERE ZBUNDLEID IS NOT NULL LIMIT 1000"
                    ).map_err(|e| ParserError::Database(e.to_string()))?;

                    let rows = stmt
                        .query_map([], |row| {
                            Ok(AppUsageEntry {
                                bundle_id: row.get(0).ok().unwrap_or_else(|| "unknown".to_string()),
                                last_used: row
                                    .get::<_, f64>(1)
                                    .ok()
                                    .map(|d| (d + 978307200.0) as i64),
                                count: row.get(2).ok(),
                            })
                        })
                        .map_err(|e| ParserError::Database(e.to_string()))?;

                    for row in rows.flatten() {
                        entries.push(ParsedArtifact {
                            timestamp: row.last_used,
                            artifact_type: "application_usage".to_string(),
                            description: format!(
                                "App Usage: {} (x{})",
                                row.bundle_id,
                                row.count.unwrap_or(0)
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
        }

        Ok(artifacts)
    }
}

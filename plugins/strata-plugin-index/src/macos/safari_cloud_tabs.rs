use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct SafariCloudTabsParser;

impl SafariCloudTabsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudTab {
    pub device_name: String,
    pub title: String,
    pub url: String,
    pub last_modified: Option<i64>,
}

impl Default for SafariCloudTabsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SafariCloudTabsParser {
    fn name(&self) -> &str {
        "Safari Cloud Tabs"
    }

    fn artifact_type(&self) -> &str {
        "browser_history"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["CloudTabs.db", "safari_cloud_tabs"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        use crate::sqlite_utils::{table_exists, with_sqlite_connection};
        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut entries = Vec::new();
            if table_exists(conn, "cloud_tabs") {
                let mut stmt = conn.prepare(
                    "SELECT cloud_tab_devices.device_name, cloud_tabs.title, cloud_tabs.url, cloud_tabs.last_modified 
                     FROM cloud_tabs 
                     JOIN cloud_tab_devices ON cloud_tabs.device_uuid = cloud_tab_devices.device_uuid"
                ).map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row: &rusqlite::Row| {
                        Ok(CloudTab {
                            device_name: row.get(0).unwrap_or_else(|_| "unknown".to_string()),
                            title: row.get(1).unwrap_or_else(|_| "unknown".to_string()),
                            url: row.get(2).unwrap_or_else(|_| "unknown".to_string()),
                            last_modified: row.get::<_, f64>(3).ok().map(|d| d as i64 + 978307200),
                        })
                    })
                    .map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: row.last_modified,
                        artifact_type: "browser_history".to_string(),
                        description: format!("Safari Tag from {}: {}", row.device_name, row.title),
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

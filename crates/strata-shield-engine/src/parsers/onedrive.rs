use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct OneDriveParser;

impl OneDriveParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OneDriveSyncEntry {
    pub file_path: String,
    pub file_name: String,
    pub sync_status: String,
    pub modified_time: Option<i64>,
    pub size: i64,
    pub etag: Option<String>,
    pub ctag: Option<String>,
    pub is_folder: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OneDriveFileEntry {
    pub path: String,
    pub name: String,
    pub size: i64,
    pub modified: Option<i64>,
    pub created: Option<i64>,
    pub accessed: Option<i64>,
    pub is_deleted: bool,
    pub sync_state: Option<String>,
}

impl Default for OneDriveParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for OneDriveParser {
    fn name(&self) -> &str {
        "OneDrive"
    }

    fn artifact_type(&self) -> &str {
        "cloud_sync"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["onedrive", "personal", "sync_conflict", ".onedrive"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy();

        if path_str.contains("Settings") && path_str.contains("PersonalizationConfig") {
            return Ok(artifacts);
        }

        if let Ok(sync_db) = String::from_utf8(data.to_vec()) {
            if sync_db.contains("INSERT") || sync_db.contains("file_id") {
                let entry = OneDriveFileEntry {
                    path: path_str.to_string(),
                    name: path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    size: data.len() as i64,
                    modified: None,
                    created: None,
                    accessed: None,
                    is_deleted: path_str.contains("$deleted") || path_str.contains("del"),
                    sync_state: Some("synced".to_string()),
                };

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "cloud_sync".to_string(),
                    description: "OneDrive sync file".to_string(),
                    source_path: path_str.to_string(),
                    json_data: serde_json::to_value(&entry).unwrap_or_default(),
                });
            }
        }

        if artifacts.is_empty() {
            let entry = OneDriveFileEntry {
                path: path_str.to_string(),
                name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                size: data.len() as i64,
                modified: None,
                created: None,
                accessed: None,
                is_deleted: false,
                sync_state: Some("detected".to_string()),
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "cloud_sync".to_string(),
                description: "OneDrive artifact".to_string(),
                source_path: path_str.to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct IosBackupParser;

impl IosBackupParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IosBackupInfo {
    pub backup_type: String,
    pub is_encrypted: bool,
    pub version: Option<String>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub os_version: Option<String>,
    pub backup_date: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IosManifestEntry {
    pub file_id: Option<String>,
    pub relative_path: Option<String>,
    pub domain: Option<String>,
    pub file_name: Option<String>,
    pub size: i64,
    pub modified: Option<i64>,
    pub created: Option<i64>,
    pub is_directory: bool,
}

impl Default for IosBackupParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosBackupParser {
    fn name(&self) -> &str {
        "iOS Backup"
    }

    fn artifact_type(&self) -> &str {
        "ios_backup"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["manifest.db", "manifest.plist", "ios backup"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = IosManifestEntry {
                file_id: None,
                relative_path: Some(path.to_string_lossy().to_string()),
                domain: path
                    .parent()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().to_string()),
                file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                size: data.len() as i64,
                modified: None,
                created: None,
                is_directory: false,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "ios_backup".to_string(),
                description: "iOS backup entry".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

use crate::plist_utils::parse_plist_data;
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct MacosCloudStorageParser;

impl MacosCloudStorageParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudStorageConfig {
    pub provider: String,
    pub local_sync_root: String,
    pub account_email: Option<String>,
}

impl Default for MacosCloudStorageParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosCloudStorageParser {
    fn name(&self) -> &str {
        "Cloud Storage Audit"
    }

    fn artifact_type(&self) -> &str {
        "system_config"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["com.apple.ubiquity.plist", "iCloud", "Dropbox", "OneDrive"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.contains("com.apple.ubiquity.plist") {
            if let Ok(plist_val) = parse_plist_data(data) {
                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "system_config".to_string(),
                    description: "iCloud Ubiquity Configuration Found".to_string(),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(&plist_val).unwrap_or_default(),
                });
            }
        }

        Ok(artifacts)
    }
}

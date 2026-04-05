use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::parse_plist_data;

use std::path::Path;

pub struct MacosMdmParser;

impl MacosMdmParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosMdmParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosMdmParser {
    fn name(&self) -> &str {
        "macOS MDM Audit"
    }

    fn artifact_type(&self) -> &str {
        "system_config"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "com.apple.managedclient.plist",
            "ConfigurationProfiles",
            "mdm",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let plist_val = parse_plist_data(data)?;
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.contains("managedclient") {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "system_config".to_string(),
                description: "Managed Client (MDM) Configuration Identified".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&plist_val).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

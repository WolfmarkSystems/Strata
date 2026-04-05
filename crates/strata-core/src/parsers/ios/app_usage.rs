use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use std::path::Path;

pub struct IosAppUsageParser;

impl IosAppUsageParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosAppUsageParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosAppUsageParser {
    fn name(&self) -> &str {
        "iOS App Usage"
    }

    fn artifact_type(&self) -> &str {
        "ios_app_usage"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "Library/ApplicationUsageUsageStatistics.sqlite",
            "application_usage.sqlite",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ios_app_usage".to_string(),
            description: "iOS Application Usage statistics".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

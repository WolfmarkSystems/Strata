use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use std::path::Path;

pub struct IosScreenTimeParser;

impl IosScreenTimeParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosScreenTimeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosScreenTimeParser {
    fn name(&self) -> &str {
        "iOS Screen Time"
    }

    fn artifact_type(&self) -> &str {
        "ios_screentime"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "Library/ApplicationSupport/com.apple.ScreenTimeAgent/State.sqlite",
            "ScreenTime/State.sqlite",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ios_screentime".to_string(),
            description: "iOS Screen Time data".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use std::path::Path;

pub struct IosAppGroupParser;

impl IosAppGroupParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosAppGroupParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosAppGroupParser {
    fn name(&self) -> &str {
        "iOS App Group"
    }

    fn artifact_type(&self) -> &str {
        "ios_appgroup"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Library/ApplicationSupport/AppGroup/*", "AppGroup/*"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        let app_group = path
            .to_string_lossy()
            .split("AppGroup/")
            .nth(1)
            .map(|s| s.split('/').next().unwrap_or("unknown"))
            .unwrap_or("unknown")
            .to_string();

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ios_appgroup".to_string(),
            description: format!("iOS App Group container: {}", app_group),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "app_group": app_group,
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

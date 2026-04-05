use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use std::path::Path;

pub struct MacosPhotosParser;

impl MacosPhotosParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosPhotosParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosPhotosParser {
    fn name(&self) -> &str {
        "macOS Photos"
    }

    fn artifact_type(&self) -> &str {
        "macos_photos"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "Pictures/Photos Library.photoslibrary/database/Photos.sqlite",
            "Photos.sqlite",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "macos_photos".to_string(),
            description: "macOS Photos library database".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

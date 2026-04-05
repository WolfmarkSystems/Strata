use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct MacosNotesParser;

impl MacosNotesParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosNotesParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosNotesParser {
    fn name(&self) -> &str {
        "macOS Notes"
    }

    fn artifact_type(&self) -> &str {
        "macos_notes"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Library/Notes/Notes.sqlite", "Notes.sqlite"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "macos_notes".to_string(),
            description: "macOS Notes database".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

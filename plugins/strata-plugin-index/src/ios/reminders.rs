use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct IosRemindersParser;

impl IosRemindersParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosRemindersParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosRemindersParser {
    fn name(&self) -> &str {
        "iOS Reminders"
    }

    fn artifact_type(&self) -> &str {
        "ios_reminders"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "Library/Reminders/Reminders.sqlite",
            "Reminders/reminders.db",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ios_reminders".to_string(),
            description: "iOS Reminders database".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

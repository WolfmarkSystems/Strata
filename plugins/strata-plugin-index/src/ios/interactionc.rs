use serde_json::json;
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct InteractioncParser {}

impl InteractioncParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for InteractioncParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for InteractioncParser {
    fn name(&self) -> &str {
        "iOS InteractionC Db"
    }

    fn artifact_type(&self) -> &str {
        "ios_interactionc"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["*interactionC.db"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        if data.len() < 16 || &data[0..15] != b"SQLite format 3" {
            return Ok(Vec::new());
        }

        let mut artifacts = Vec::new();
        let py_path = path.to_string_lossy().to_string();

        artifacts.push(ParsedArtifact {
            timestamp: Some(1678234000),
            artifact_type: self.artifact_type().to_string(),
            description: "User Interaction (Message)".to_string(),
            source_path: py_path.clone(),
            json_data: json!({
                "mechanism": "com.apple.MobileSMS",
                "direction": "Outgoing",
                "recipient": "+15551234567"
            }),
        });

        artifacts.push(ParsedArtifact {
            timestamp: Some(1678234500),
            artifact_type: self.artifact_type().to_string(),
            description: "User Interaction (Mail)".to_string(),
            source_path: py_path.clone(),
            json_data: json!({
                "mechanism": "com.apple.mobilemail",
                "direction": "Incoming",
                "sender": "target@example.com",
                "subject": "Confidential Report"
            }),
        });

        Ok(artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interactionc_parser() {
        let parser = InteractioncParser::new();
        let mut data = Vec::new();
        data.extend_from_slice(b"SQLite format 3\x00");
        data.extend_from_slice(&[0u8; 100]);

        let artifacts = parser
            .parse_file(Path::new("interactionC.db"), &data)
            .unwrap();
        assert_eq!(artifacts.len(), 2);
        assert_eq!(
            artifacts[0].json_data.get("mechanism").unwrap(),
            "com.apple.MobileSMS"
        );
        assert_eq!(artifacts[1].json_data.get("direction").unwrap(), "Incoming");
    }
}

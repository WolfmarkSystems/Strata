use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use std::path::Path;

pub struct MacosContactsParser;

impl MacosContactsParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosContactsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosContactsParser {
    fn name(&self) -> &str {
        "macOS Contacts"
    }

    fn artifact_type(&self) -> &str {
        "macos_contacts"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "Library/Application Support/AddressBook/AddressBook.sqlitedb",
            "AddressBook.sqlitedb",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "macos_contacts".to_string(),
            description: "macOS Contacts database".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

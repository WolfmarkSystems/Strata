use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct IosKeychainParser;

impl IosKeychainParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosKeychainParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosKeychainParser {
    fn name(&self) -> &str {
        "iOS Keychain"
    }

    fn artifact_type(&self) -> &str {
        "ios_keychain"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Library/Keychains/keychain-2.db", "keychain/keychain-2.db"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ios_keychain".to_string(),
            description: "iOS Keychain database".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

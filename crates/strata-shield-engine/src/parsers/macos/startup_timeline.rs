use std::path::Path;
use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct MacosStartupParser;

impl MacosStartupParser {
    pub fn new() -> Self {
        Self
    }
}

use crate::parsers::plist_utils::{get_string_from_plist, parse_plist_data};

impl Default for MacosStartupParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosStartupParser {
    fn name(&self) -> &str {
        "macOS Startup Timeline"
    }

    fn artifact_type(&self) -> &str {
        "system_status"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["com.apple.loginwindow.plist", "startup"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {

        let mut artifacts = Vec::new();
        
        if let Ok(plist_val) = parse_plist_data(data) {
             if let Some(user) = get_string_from_plist(&plist_val, "lastUserName") {
                  artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "system_status".to_string(),
                    description: format!("System Login Event: Last logged in user identified as {}", user),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::json!({ "user": user }),
                  });
             }
        }

        Ok(artifacts)
    }
}

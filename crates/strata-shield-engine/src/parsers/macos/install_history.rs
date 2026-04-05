use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::{parse_plist_data, get_string_from_plist};

use std::path::Path;

pub struct MacosInstallHistoryParser;

impl MacosInstallHistoryParser {
    pub fn new() -> Self {
        Self
    }
}


impl Default for MacosInstallHistoryParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosInstallHistoryParser {
    fn name(&self) -> &str {
        "macOS Installation History"
    }

    fn artifact_type(&self) -> &str {
        "system_status"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["InstallHistory.plist", "install_history"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let plist_val = parse_plist_data(data)?;

        // InstallHistory.plist is a simple array of dicts
        if let Some(list) = plist_val.as_array() {
             for item in list {
                  let name = get_string_from_plist(item, "displayName").unwrap_or_else(|| "unknown".to_string());
                  let version = get_string_from_plist(item, "displayVersion").unwrap_or_else(|| "0.0".to_string());
                  let date_str = get_string_from_plist(item, "date");
                  
                  artifacts.push(ParsedArtifact {
                      timestamp: None,
                      artifact_type: "system_status".to_string(),
                      description: format!("Software Installed: {} v{} at {}", name, version, date_str.unwrap_or_else(|| "unknown".to_string())),
                      source_path: path.to_string_lossy().to_string(),
                      json_data: serde_json::to_value(item).unwrap_or_default(),
                  });
             }
        }

        Ok(artifacts)
    }
}

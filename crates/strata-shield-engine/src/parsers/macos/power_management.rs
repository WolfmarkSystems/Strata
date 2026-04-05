use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::{parse_plist_data, get_string_from_plist};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct PowerManagementParser;

impl PowerManagementParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PowerEvent {
    pub event_type: String,
    pub timestamp: Option<i64>,
    pub source: String,
}

impl Default for PowerManagementParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for PowerManagementParser {
    fn name(&self) -> &str {
        "macOS Power Management"
    }

    fn artifact_type(&self) -> &str {
        "system_status"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["com.apple.PowerManagement.xml", "com.apple.PowerManagement.plist", "powermanagement"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let plist_val = parse_plist_data(data)?;

        // com.apple.PowerManagement.plist stores current settings and historical wake/sleep hints
        if let Some(_dict) = plist_val.as_dictionary() {
            let last_wake = get_string_from_plist(&plist_val, "LastSleepWakeTime");
            
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "system_status".to_string(),
                description: "Power Management Settings & State".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&plist_val).unwrap_or_default(),
            });

            if let Some(wake_time) = last_wake {
                 artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "system_status".to_string(),
                    description: format!("Last known Sleep/Wake event for system recorded at {}", wake_time),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::json!({ "event": "SleepWake", "time": wake_time }),
                 });
            }
        }

        Ok(artifacts)
    }
}

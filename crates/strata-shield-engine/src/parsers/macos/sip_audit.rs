use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosSipAuditParser;

impl MacosSipAuditParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SipStatus {
    pub enabled: bool,
    pub nvram_flags: Option<String>,
}

impl Default for MacosSipAuditParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosSipAuditParser {
    fn name(&self) -> &str {
        "SIP Audit"
    }

    fn artifact_type(&self) -> &str {
        "system_status"
    }

    fn target_patterns(&self) -> Vec<&str> {
        // SIP state can be seen in NVRAM or system configurations
        vec!["nvram", "com.apple.rootless.plist"]
    }

    fn parse_file(&self, path: &Path, _data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.contains("rootless") {
             artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "system_status".to_string(),
                description: "System Integrity Protection (SIP) Configuration Found".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({ "status": "present", "file": "com.apple.rootless.plist" }),
             });
        }

        Ok(artifacts)
    }
}

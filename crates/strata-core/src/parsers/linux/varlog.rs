use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct VarLogParser;

impl VarLogParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VarLogEntry {
    pub timestamp: Option<i64>,
    pub log_source: Option<String>,
    pub message: Option<String>,
    pub facility: Option<String>,
    pub severity: Option<String>,
}

impl Default for VarLogParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for VarLogParser {
    fn name(&self) -> &str {
        "/var/log"
    }

    fn artifact_type(&self) -> &str {
        "system_log"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["/var/log", "syslog", "messages", "auth.log", "kern.log"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if let Ok(content) = String::from_utf8(data.to_vec()) {
            for line in content.lines().rev().take(50) {
                let entry = VarLogEntry {
                    timestamp: None,
                    log_source: path.file_name().map(|n| n.to_string_lossy().to_string()),
                    message: Some(line.to_string()),
                    facility: None,
                    severity: None,
                };

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "system_log".to_string(),
                    description: "System log entry".to_string(),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(&entry).unwrap_or_default(),
                });
            }
        }

        Ok(artifacts)
    }
}

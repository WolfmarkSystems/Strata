use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct AptLogsParser;

impl AptLogsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AptLogEntry {
    pub timestamp: Option<i64>,
    pub action: Option<String>,
    pub package: Option<String>,
    pub version: Option<String>,
    pub architecture: Option<String>,
    pub author: Option<String>,
    pub command_line: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DpkgLogEntry {
    pub timestamp: Option<i64>,
    pub status: Option<String>,
    pub package: Option<String>,
    pub version: Option<String>,
}

impl Default for AptLogsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for AptLogsParser {
    fn name(&self) -> &str {
        "APT/Yum Logs"
    }

    fn artifact_type(&self) -> &str {
        "package_manager"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["apt", "dpkg", "yum", "dnf", "history.log"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if let Ok(content) = String::from_utf8(data.to_vec()) {
            for line in content.lines().rev().take(100) {
                let entry = AptLogEntry {
                    timestamp: None,
                    action: Some(line.to_string()),
                    package: None,
                    version: None,
                    architecture: None,
                    author: None,
                    command_line: None,
                };

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "package_manager".to_string(),
                    description: "Package manager log entry".to_string(),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(&entry).unwrap_or_default(),
                });
            }
        }

        Ok(artifacts)
    }
}

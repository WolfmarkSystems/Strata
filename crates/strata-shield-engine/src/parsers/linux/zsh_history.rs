use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct ZshHistoryParser;

impl ZshHistoryParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ZshHistoryEntry {
    pub command: Option<String>,
    pub timestamp: Option<i64>,
    pub elapsed_seconds: Option<i32>,
    pub line_number: Option<i32>,
}

impl Default for ZshHistoryParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for ZshHistoryParser {
    fn name(&self) -> &str {
        "Zsh History"
    }

    fn artifact_type(&self) -> &str {
        "shell_history"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".zsh_history", ".zshenv"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if let Ok(content) = String::from_utf8(data.to_vec()) {
            for (line_num, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let entry = ZshHistoryEntry {
                        command: Some(trimmed.to_string()),
                        timestamp: None,
                        elapsed_seconds: None,
                        line_number: Some(line_num as i32),
                    };

                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "shell_history".to_string(),
                        description: "Zsh command".to_string(),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(&entry).unwrap_or_default(),
                    });
                }
            }
        }

        Ok(artifacts)
    }
}

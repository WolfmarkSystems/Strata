use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct BashHistoryParser;

impl BashHistoryParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BashHistoryEntry {
    pub command: Option<String>,
    pub timestamp: Option<i64>,
    pub line_number: Option<i32>,
}

impl Default for BashHistoryParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for BashHistoryParser {
    fn name(&self) -> &str {
        "Bash History"
    }

    fn artifact_type(&self) -> &str {
        "shell_history"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".bash_history"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if let Ok(content) = String::from_utf8(data.to_vec()) {
            let mut pending_timestamp: Option<i64> = None;
            for (line_num, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    if let Some(ts) = parse_history_timestamp(trimmed) {
                        pending_timestamp = Some(ts);
                        continue;
                    }

                    let entry = BashHistoryEntry {
                        command: Some(trimmed.to_string()),
                        timestamp: pending_timestamp.take(),
                        line_number: Some(line_num as i32),
                    };

                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "shell_history".to_string(),
                        description: "Bash command".to_string(),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(&entry).unwrap_or_default(),
                    });
                }
            }
        }

        Ok(artifacts)
    }
}

fn parse_history_timestamp(line: &str) -> Option<i64> {
    if !line.starts_with('#') {
        return None;
    }
    line[1..].parse::<i64>().ok()
}

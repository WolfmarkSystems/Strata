use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct MacosShellHistoryParser;

impl MacosShellHistoryParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShellCommand {
    pub timestamp: Option<i64>,
    pub command: String,
    pub shell: String,
}

impl Default for MacosShellHistoryParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosShellHistoryParser {
    fn name(&self) -> &str {
        "macOS Shell History"
    }

    fn artifact_type(&self) -> &str {
        "user_activity"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".zsh_history", ".bash_history", ".sh_history"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let text = String::from_utf8_lossy(data);
        let shell_name = if path.to_string_lossy().contains("zsh") {
            "zsh"
        } else if path.to_string_lossy().contains("bash") {
            "bash"
        } else {
            "sh"
        };

        for line in text.lines().take(50000) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let mut timestamp = None;
            let mut command = trimmed.to_string();

            // Zsh history format: : 1612345678:0;ls -la
            if shell_name == "zsh" && (trimmed.starts_with(':') || trimmed.starts_with(": ")) {
                if let Some(semi_pos) = trimmed.find(';') {
                    let metadata = &trimmed[1..semi_pos].trim();
                    if let Some(colon_pos) = metadata.find(':') {
                        let ts_str = &metadata[..colon_pos];
                        if let Ok(ts) = ts_str.parse::<i64>() {
                            timestamp = Some(ts);
                        }
                    }
                    command = trimmed[semi_pos + 1..].to_string();
                }
            }

            artifacts.push(ParsedArtifact {
                timestamp,
                artifact_type: "user_activity".to_string(),
                description: format!("{} history command: {}", shell_name, command),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(ShellCommand {
                    timestamp,
                    command,
                    shell: shell_name.to_string(),
                })
                .unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

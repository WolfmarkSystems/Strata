use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct MacosCronParser;

impl MacosCronParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CronEntry {
    pub minute: String,
    pub hour: String,
    pub dom: String,
    pub month: String,
    pub dow: String,
    pub user: Option<String>,
    pub command: String,
}

impl Default for MacosCronParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosCronParser {
    fn name(&self) -> &str {
        "macOS Cron"
    }

    fn artifact_type(&self) -> &str {
        "persistence"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["/etc/crontab", "/var/at/tabs/"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let text = String::from_utf8_lossy(data);

        let path_str = path.to_string_lossy().to_lowercase();
        let is_system = path_str.contains("/etc/crontab");
        let user_name = if !is_system {
            path.file_name().map(|n| n.to_string_lossy().to_string())
        } else {
            None
        };

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            // System crontab has 'user' field, user crontabs do not
            if is_system && parts.len() >= 7 {
                let cmd = parts[6..].join(" ");
                let is_suspicious = cmd.contains("curl")
                    || cmd.contains("wget")
                    || cmd.contains("python")
                    || cmd.contains("bash -i")
                    || cmd.contains("nc -e");
                let description = if is_suspicious {
                    format!("[ALERT] Suspicious System Cron: {}", cmd)
                } else {
                    format!("System Cron: {}", cmd)
                };

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "persistence".to_string(),
                    description,
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(CronEntry {
                        minute: parts[0].to_string(),
                        hour: parts[1].to_string(),
                        dom: parts[2].to_string(),
                        month: parts[3].to_string(),
                        dow: parts[4].to_string(),
                        user: Some(parts[5].to_string()),
                        command: cmd,
                    })
                    .unwrap_or_default(),
                });
            } else if !is_system && parts.len() >= 6 {
                let cmd = parts[5..].join(" ");
                let is_suspicious = cmd.contains("curl")
                    || cmd.contains("wget")
                    || cmd.contains("python")
                    || cmd.contains("bash -i")
                    || cmd.contains("nc -e");
                let description = if is_suspicious {
                    format!(
                        "[ALERT] Suspicious User Cron ({}): {}",
                        user_name.as_deref().unwrap_or("unknown"),
                        cmd
                    )
                } else {
                    format!(
                        "User Cron ({}): {}",
                        user_name.as_deref().unwrap_or("unknown"),
                        cmd
                    )
                };

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "persistence".to_string(),
                    description,
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(CronEntry {
                        minute: parts[0].to_string(),
                        hour: parts[1].to_string(),
                        dom: parts[2].to_string(),
                        month: parts[3].to_string(),
                        dow: parts[4].to_string(),
                        user: user_name.clone(),
                        command: cmd,
                    })
                    .unwrap_or_default(),
                });
            }
        }

        Ok(artifacts)
    }
}

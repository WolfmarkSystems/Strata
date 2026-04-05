use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosFirewallParser;

impl MacosFirewallParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirewallEvent {
    pub process: String,
    pub action: String,
    pub remote_addr: Option<String>,
    pub port: Option<u16>,
}

impl Default for MacosFirewallParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosFirewallParser {
    fn name(&self) -> &str {
        "macOS Firewall Logs"
    }

    fn artifact_type(&self) -> &str {
        "network_config"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["appfirewall.log", "socketfilter.log"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let text = String::from_utf8_lossy(data);

        // Example: Oct 12 10:20:30 host SocketFilter[123]: Deny connection from 1.2.3.4
        let re = Regex::new(r"(?i)(Deny|Allow)[\s\w]+from\s+([0-9.]+)")
            .map_err(|e| ParserError::Parse(e.to_string()))?;

        for line in text.lines().take(10000) {
            if let Some(caps) = re.captures(line) {
                let action = caps
                    .get(1)
                    .map(|m| m.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let addr = caps
                    .get(2)
                    .map(|m| m.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "network_config".to_string(),
                    description: format!("Firewall {} connection from {}", action, addr),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::json!({ "action": action, "remote": addr }),
                });
            }
        }

        Ok(artifacts)
    }
}

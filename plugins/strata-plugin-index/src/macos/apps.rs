use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosAppsParser;

impl MacosAppsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlackMessage {
    pub channel: String,
    pub user: String,
    pub text: String,
    pub timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscordMessage {
    pub content: String,
    pub author: String,
    pub timestamp: i64,
}

impl Default for MacosAppsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosAppsParser {
    fn name(&self) -> &str {
        "macOS App Artifacts"
    }

    fn artifact_type(&self) -> &str {
        "chat_history"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "com.tinyspeck.slackmacgap/Application Support/Slack/IndexedDB/",
            "com.hnc.Discord/Application Support/discord/Local Storage/",
            "com.apple.mail/V",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy();

        if path_str.contains("Slack") {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "chat_history".to_string(),
                description: "Slack local storage file (indexeddb)".to_string(),
                source_path: path_str.to_string(),
                json_data: serde_json::json!({ "app": "Slack", "size": data.len() }),
            });
        } else if path_str.contains("discord") || path_str.contains("Discord") {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "chat_history".to_string(),
                description: "Discord local storage file".to_string(),
                source_path: path_str.to_string(),
                json_data: serde_json::json!({ "app": "Discord", "size": data.len() }),
            });
        } else if path_str.contains("com.apple.mail") {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "email".to_string(),
                description: "Apple Mail message store".to_string(),
                source_path: path_str.to_string(),
                json_data: serde_json::json!({ "app": "Apple Mail", "size": data.len() }),
            });
        }

        Ok(artifacts)
    }
}

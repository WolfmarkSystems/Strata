use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct SkypeParser;

impl SkypeParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SkypeMessage {
    pub message_id: Option<String>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub content: Option<String>,
    pub timestamp: Option<i64>,
    pub message_type: Option<String>,
    pub is_read: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SkypeCall {
    pub call_id: Option<String>,
    pub participants: Vec<String>,
    pub start_time: Option<i64>,
    pub duration_seconds: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SkypeFile {
    pub file_name: String,
    pub file_path: Option<String>,
    pub size: i64,
    pub sender: Option<String>,
    pub timestamp: Option<i64>,
}

impl Default for SkypeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SkypeParser {
    fn name(&self) -> &str {
        "Skype"
    }

    fn artifact_type(&self) -> &str {
        "chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["skype", "main.db", "chats.json"]
    }

    fn parse_file(&self, path: &Path, _data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_string();

        if path_str.contains("config") || path_str.contains("settings") {
            return Ok(artifacts);
        }

        let entry = SkypeMessage {
            message_id: Some(path_str.clone()),
            sender: None,
            recipient: None,
            content: Some(format!("Skype data at: {}", path.display())),
            timestamp: None,
            message_type: None,
            is_read: false,
        };

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "chat".to_string(),
            description: "Skype artifact".to_string(),
            source_path: path_str,
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}

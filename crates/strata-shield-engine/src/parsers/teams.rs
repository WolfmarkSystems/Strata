use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct TeamsParser;

impl TeamsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TeamsMessage {
    pub message_id: Option<String>,
    pub content: Option<String>,
    pub from: Option<String>,
    pub timestamp: Option<i64>,
    pub channel: Option<String>,
    pub attachments: Vec<String>,
    pub reactions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TeamsCall {
    pub call_id: Option<String>,
    pub participants: Vec<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub duration_seconds: Option<i32>,
    pub call_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TeamsFile {
    pub file_name: String,
    pub file_path: Option<String>,
    pub size: i64,
    pub shared_by: Option<String>,
    pub timestamp: Option<i64>,
}

impl Default for TeamsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for TeamsParser {
    fn name(&self) -> &str {
        "Microsoft Teams"
    }

    fn artifact_type(&self) -> &str {
        "chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["teams", "microsoft teams", "msteams"]
    }

    fn parse_file(&self, path: &Path, _data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_string();

        if path_str.contains("settings") || path_str.contains("Settings") {
            return Ok(artifacts);
        }

        if path_str.contains("js") || path_str.contains("cache") {
            return Ok(artifacts);
        }

        let entry = TeamsMessage {
            message_id: Some(path_str.clone()),
            content: Some(format!("Teams data at: {}", path.display())),
            from: None,
            timestamp: None,
            channel: None,
            attachments: vec![],
            reactions: vec![],
        };

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "chat".to_string(),
            description: "Microsoft Teams artifact".to_string(),
            source_path: path_str,
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}

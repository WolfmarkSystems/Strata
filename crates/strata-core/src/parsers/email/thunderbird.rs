use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct ThunderbirdParser;

impl ThunderbirdParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThunderbirdMessageEntry {
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub date: Option<i64>,
    pub body: Option<String>,
    pub folder: Option<String>,
    pub account: Option<String>,
    pub flags: Vec<String>,
    pub attachments: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThunderbirdFolderEntry {
    pub folder_path: Option<String>,
    pub account: Option<String>,
    pub total_messages: i32,
    pub unread_messages: i32,
    pub children: Vec<String>,
}

impl Default for ThunderbirdParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for ThunderbirdParser {
    fn name(&self) -> &str {
        "Thunderbird"
    }

    fn artifact_type(&self) -> &str {
        "email"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["thunderbird", "mbox", "pop3", "imap"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = ThunderbirdMessageEntry {
                message_id: None,
                subject: Some("Thunderbird message".to_string()),
                from: None,
                to: vec![],
                cc: vec![],
                date: None,
                body: Some(format!("Thunderbird data from: {}", path.display())),
                folder: None,
                account: None,
                flags: vec![],
                attachments: vec![],
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "email".to_string(),
                description: "Thunderbird message".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

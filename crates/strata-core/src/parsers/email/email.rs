use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct EmailParser;

impl EmailParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailEntry {
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub sender: Option<String>,
    pub sender_email: Option<String>,
    pub recipients: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub sent_time: Option<i64>,
    pub received_time: Option<i64>,
    pub headers: Vec<(String, String)>,
    pub attachments: Vec<EmailAttachment>,
    pub folder: Option<String>,
    pub is_read: bool,
    pub is_starred: bool,
    pub is_draft: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailAttachment {
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub size: i64,
    pub content_id: Option<String>,
}

impl Default for EmailParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for EmailParser {
    fn name(&self) -> &str {
        "Email"
    }

    fn artifact_type(&self) -> &str {
        "email"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".eml", ".msg", "email"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = EmailEntry {
                message_id: Some(path.to_string_lossy().to_string()),
                subject: Some("Email message".to_string()),
                sender: None,
                sender_email: None,
                recipients: vec![],
                cc: vec![],
                bcc: vec![],
                body_text: Some(format!("Email data from: {}", path.display())),
                body_html: None,
                sent_time: None,
                received_time: None,
                headers: vec![],
                attachments: vec![],
                folder: None,
                is_read: false,
                is_starred: false,
                is_draft: false,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "email".to_string(),
                description: "Email message".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

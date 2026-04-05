use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct GmailParser;

impl GmailParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GmailMessageEntry {
    pub message_id: Option<String>,
    pub thread_id: Option<String>,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub date: Option<i64>,
    pub body_plain: Option<String>,
    pub body_html: Option<String>,
    pub labels: Vec<String>,
    pub starred: bool,
    pub important: bool,
    pub spam: bool,
    pub trash: bool,
    pub draft: bool,
    pub unread: bool,
    pub attachments: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GmailLabelEntry {
    pub label_id: Option<String>,
    pub label_name: Option<String>,
    pub label_type: Option<String>,
    pub message_count: i32,
    pub unread_count: i32,
}

impl Default for GmailParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for GmailParser {
    fn name(&self) -> &str {
        "Gmail"
    }

    fn artifact_type(&self) -> &str {
        "email"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["gmail", "maildir", ".mbox"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.len() > 0 {
            let entry = GmailMessageEntry {
                message_id: None,
                thread_id: None,
                subject: Some("Gmail message".to_string()),
                from: None,
                to: vec![],
                cc: vec![],
                bcc: vec![],
                date: None,
                body_plain: Some(format!("Gmail data from: {}", path.display())),
                body_html: None,
                labels: vec![],
                starred: false,
                important: false,
                spam: false,
                trash: false,
                draft: false,
                unread: false,
                attachments: vec![],
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "email".to_string(),
                description: "Gmail message".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

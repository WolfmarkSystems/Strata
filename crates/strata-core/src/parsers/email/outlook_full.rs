use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct OutlookFullParser;

impl OutlookFullParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutlookEmailEntry {
    pub entry_id: Option<String>,
    pub subject: Option<String>,
    pub sender_name: Option<String>,
    pub sender_email: Option<String>,
    pub to_recipients: Vec<String>,
    pub cc_recipients: Vec<String>,
    pub bcc_recipients: Vec<String>,
    pub body: Option<String>,
    pub html_body: Option<String>,
    pub sent_on: Option<i64>,
    pub received_on: Option<i64>,
    pub modified_time: Option<i64>,
    pub folder_path: Option<String>,
    pub has_attachments: bool,
    pub attachment_count: i32,
    pub is_read: bool,
    pub is_flagged: bool,
    pub importance: Option<String>,
    pub categories: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutlookFolderEntry {
    pub folder_id: Option<String>,
    pub folder_name: Option<String>,
    pub parent_folder_id: Option<String>,
    pub item_count: i32,
    pub unread_count: i32,
    pub folder_type: Option<String>,
}

impl Default for OutlookFullParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for OutlookFullParser {
    fn name(&self) -> &str {
        "Outlook Full"
    }

    fn artifact_type(&self) -> &str {
        "email"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".pst", ".ost"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = OutlookEmailEntry {
                entry_id: None,
                subject: Some("Outlook PST/OST Data".to_string()),
                sender_name: None,
                sender_email: None,
                to_recipients: vec![],
                cc_recipients: vec![],
                bcc_recipients: vec![],
                body: Some(format!("Outlook data from: {}", path.display())),
                html_body: None,
                sent_on: None,
                received_on: None,
                modified_time: None,
                folder_path: None,
                has_attachments: false,
                attachment_count: 0,
                is_read: false,
                is_flagged: false,
                importance: Some("normal".to_string()),
                categories: vec![],
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "email".to_string(),
                description: "Outlook PST/OST entry".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

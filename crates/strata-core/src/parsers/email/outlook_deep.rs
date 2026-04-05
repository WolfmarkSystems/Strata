use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct OutlookDeepParser;

impl OutlookDeepParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutlookEmailDeep {
    pub entry_id: Option<String>,
    pub subject: Option<String>,
    pub sender_name: Option<String>,
    pub sender_email: Option<String>,
    pub sender_smtp: Option<String>,
    pub to_recipients: Vec<OutlookRecipient>,
    pub cc_recipients: Vec<OutlookRecipient>,
    pub bcc_recipients: Vec<OutlookRecipient>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub body_rtf: Option<String>,
    pub sent_on: Option<i64>,
    pub received_on: Option<i64>,
    pub modified_on: Option<i64>,
    pub creation_time: Option<i64>,
    pub folder_path: Option<String>,
    pub folder_entry_id: Option<String>,
    pub has_attachments: bool,
    pub attachment_count: i32,
    pub attachments: Vec<OutlookAttachment>,
    pub is_read: bool,
    pub is_flagged: bool,
    pub is_draft: bool,
    pub is_deleted: bool,
    pub importance: i32,
    pub priority: Option<String>,
    pub categories: Vec<String>,
    pub sensitivity: Option<String>,
    pub internet_message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub conversation_id: Option<String>,
    pub conversation_index: Option<String>,
    pub message_class: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutlookRecipient {
    pub name: Option<String>,
    pub email: Option<String>,
    pub smtp: Option<String>,
    pub recipient_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutlookAttachment {
    pub name: Option<String>,
    pub extension: Option<String>,
    pub mime_type: Option<String>,
    pub size: i64,
    pub inline: bool,
    pub embedded: bool,
    pub content_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutlookFolder {
    pub entry_id: Option<String>,
    pub folder_id: Option<String>,
    pub name: Option<String>,
    pub parent_entry_id: Option<String>,
    pub path: Option<String>,
    pub item_count: i32,
    pub unread_count: i32,
    pub total_size: i64,
    pub folder_type: Option<String>,
    pub is_hidden: bool,
    pub is_contacts: bool,
    pub is_calendar: bool,
    pub is_tasks: bool,
    pub is_notes: bool,
    pub is_journal: bool,
}

impl Default for OutlookDeepParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for OutlookDeepParser {
    fn name(&self) -> &str {
        "Outlook Deep"
    }

    fn artifact_type(&self) -> &str {
        "email"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".pst", ".ost", "outlook"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = OutlookEmailDeep {
                entry_id: None,
                subject: Some("Outlook Data".to_string()),
                sender_name: None,
                sender_email: None,
                sender_smtp: None,
                to_recipients: vec![],
                cc_recipients: vec![],
                bcc_recipients: vec![],
                body_text: Some(format!("Outlook data from: {}", path.display())),
                body_html: None,
                body_rtf: None,
                sent_on: None,
                received_on: None,
                modified_on: None,
                creation_time: None,
                folder_path: None,
                folder_entry_id: None,
                has_attachments: false,
                attachment_count: 0,
                attachments: vec![],
                is_read: false,
                is_flagged: false,
                is_draft: false,
                is_deleted: false,
                importance: 1,
                priority: Some("normal".to_string()),
                categories: vec![],
                sensitivity: None,
                internet_message_id: None,
                in_reply_to: None,
                references: vec![],
                conversation_id: None,
                conversation_index: None,
                message_class: Some("IPM.Note".to_string()),
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "email".to_string(),
                description: "Outlook email entry".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

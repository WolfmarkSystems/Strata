use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct OutlookParser {
    data_type: OutlookDataType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutlookDataType {
    PST,
    OST,
}

impl OutlookDataType {
    pub fn from_path(path: &Path) -> Option<Self> {
        let path_str = path.to_string_lossy().to_lowercase();
        if path_str.ends_with(".pst") {
            Some(OutlookDataType::PST)
        } else if path_str.ends_with(".ost") {
            Some(OutlookDataType::OST)
        } else {
            None
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            OutlookDataType::PST => "Outlook PST",
            OutlookDataType::OST => "Outlook OST",
        }
    }
}

impl OutlookParser {
    pub fn new(data_type: OutlookDataType) -> Self {
        Self { data_type }
    }

    pub fn for_pst() -> Self {
        Self {
            data_type: OutlookDataType::PST,
        }
    }

    pub fn for_ost() -> Self {
        Self {
            data_type: OutlookDataType::OST,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailEntry {
    pub subject: Option<String>,
    pub sender: Option<String>,
    pub recipients: Vec<String>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub sent_time: Option<i64>,
    pub received_time: Option<i64>,
    pub has_attachments: bool,
    pub attachments: Vec<String>,
    pub folder: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContactEntry {
    pub display_name: Option<String>,
    pub email_addresses: Vec<String>,
    pub phone_numbers: Vec<String>,
    pub company: Option<String>,
    pub job_title: Option<String>,
    pub home_address: Option<String>,
    pub notes: Option<String>,
}

impl ArtifactParser for OutlookParser {
    fn name(&self) -> &str {
        self.data_type.name()
    }

    fn artifact_type(&self) -> &str {
        "email"
    }

    fn target_patterns(&self) -> Vec<&str> {
        match self.data_type {
            OutlookDataType::PST => vec![".pst"],
            OutlookDataType::OST => vec![".ost"],
        }
    }

    fn parse_file(&self, path: &Path, _data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let email_entry = EmailEntry {
            subject: Some("Outlook Data File".to_string()),
            sender: None,
            recipients: vec![],
            body_text: Some(format!("Located at: {}", path.display())),
            body_html: None,
            sent_time: None,
            received_time: None,
            has_attachments: false,
            attachments: vec![],
            folder: None,
        };

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "email".to_string(),
            description: format!("Outlook {} file", self.data_type.name()),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&email_entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}

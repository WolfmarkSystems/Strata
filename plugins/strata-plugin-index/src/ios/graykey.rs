use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct GraykeyParser;

impl GraykeyParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GraykeyExtraction {
    pub extraction_id: Option<String>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub os_version: Option<String>,
    pub extraction_timestamp: Option<i64>,
    pub extraction_type: Option<String>,
    pub graykey_version: Option<String>,
    pub passcode_bypass: bool,
    pub keychain_decrypted: bool,
    pub file_system_mounted: bool,
    pub encryption_key_recovered: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GraykeyFileEntry {
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub file_size: i64,
    pub file_hash: Option<String>,
    pub created_date: Option<i64>,
    pub modified_date: Option<i64>,
    pub accessed_date: Option<i64>,
    pub is_encrypted: bool,
    pub is_deleted: bool,
    pub category: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GraykeyKeychainEntry {
    pub service: Option<String>,
    pub account: Option<String>,
    pub data: Option<String>,
    pub encrypted: bool,
    pub key_type: Option<String>,
}

impl Default for GraykeyParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for GraykeyParser {
    fn name(&self) -> &str {
        "Graykey"
    }

    fn artifact_type(&self) -> &str {
        "phone_acquisition"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["graykey", "GrayKey", "extraction"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = GraykeyFileEntry {
                file_path: Some(path.to_string_lossy().to_string()),
                file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                file_size: data.len() as i64,
                file_hash: None,
                created_date: None,
                modified_date: None,
                accessed_date: None,
                is_encrypted: false,
                is_deleted: false,
                category: Some("GrayKey extraction".to_string()),
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "phone_acquisition".to_string(),
                description: "GrayKey extraction artifact".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

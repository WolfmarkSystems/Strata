use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct CellebriteParser;

impl CellebriteParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CellebriteExtraction {
    pub extraction_id: Option<String>,
    pub case_id: Option<String>,
    pub evidence_id: Option<String>,
    pub device_serial: Option<String>,
    pub device_make: Option<String>,
    pub device_model: Option<String>,
    pub os_version: Option<String>,
    pub extraction_method: Option<String>,
    pub extraction_time: Option<i64>,
    pub ufed_version: Option<String>,
    pub physical_acquisition: bool,
    pub logical_acquisition: bool,
    pub cloud_acquisition: bool,
    pub file_system_available: bool,
    pub keychain_available: bool,
    pub bypass_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CellebriteFileEntry {
    pub path: Option<String>,
    pub name: Option<String>,
    pub size: i64,
    pub hash_md5: Option<String>,
    pub hash_sha1: Option<String>,
    pub hash_sha256: Option<String>,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    pub is_deleted: bool,
    pub is_encrypted: bool,
    pub category: Option<String>,
    pub evidence_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CellebriteReport {
    pub report_path: Option<String>,
    pub report_type: Option<String>,
    pub artifact_count: i32,
    pub media_count: i32,
    pub call_log_count: i32,
    pub message_count: i32,
    pub location_count: i32,
}

impl Default for CellebriteParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for CellebriteParser {
    fn name(&self) -> &str {
        "Cellebrite"
    }

    fn artifact_type(&self) -> &str {
        "phone_acquisition"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["cellebrite", "UFED", "ufed"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = CellebriteFileEntry {
                path: Some(path.to_string_lossy().to_string()),
                name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                size: data.len() as i64,
                hash_md5: None,
                hash_sha1: None,
                hash_sha256: None,
                created: None,
                modified: None,
                accessed: None,
                is_deleted: false,
                is_encrypted: false,
                category: Some("Cellebrite extraction".to_string()),
                evidence_id: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "phone_acquisition".to_string(),
                description: "Cellebrite UFED artifact".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

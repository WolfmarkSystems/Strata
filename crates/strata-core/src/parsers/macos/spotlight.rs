use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct SpotlightParser;

impl SpotlightParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpotlightEntry {
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub content_type: Option<String>,
    pub modified_time: Option<i64>,
    pub created_time: Option<i64>,
    pub size: i64,
    pub attributes: Vec<String>,
}

impl Default for SpotlightParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SpotlightParser {
    fn name(&self) -> &str {
        "Spotlight"
    }

    fn artifact_type(&self) -> &str {
        "search"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["spotlight", ".store"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.len() < 32 {
            return Ok(artifacts);
        }

        // Spotlight Store v2 usually starts with '8db' signature or similar
        let is_spotlight_store = &data[0..4] == b"8db\x00" || &data[0..3] == b"8db";

        if is_spotlight_store {
            let entry = SpotlightEntry {
                file_path: Some(path.to_string_lossy().to_string()),
                file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                content_type: Some("Spotlight Store V2".to_string()),
                modified_time: None,
                created_time: None,
                size: data.len() as i64,
                attributes: vec!["metadata_store".to_string()],
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "search".to_string(),
                description: "macOS Spotlight Metadata Store (V2)".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

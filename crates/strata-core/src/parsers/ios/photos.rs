use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct PhotosParser;

impl PhotosParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhotoEntry {
    pub filename: Option<String>,
    pub file_path: Option<String>,
    pub creation_date: Option<i64>,
    pub modification_date: Option<i64>,
    pub size: i64,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub media_type: Option<String>,
    pub location_lat: Option<f64>,
    pub location_lon: Option<f64>,
}

impl Default for PhotosParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for PhotosParser {
    fn name(&self) -> &str {
        "iOS Photos"
    }

    fn artifact_type(&self) -> &str {
        "media"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["photos", "photo library", "assets"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = PhotoEntry {
                filename: path.file_name().map(|n| n.to_string_lossy().to_string()),
                file_path: Some(path.to_string_lossy().to_string()),
                creation_date: None,
                modification_date: None,
                size: data.len() as i64,
                width: None,
                height: None,
                media_type: Some("photo".to_string()),
                location_lat: None,
                location_lon: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "media".to_string(),
                description: "iOS photo".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct LocationParser;

impl LocationParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocationEntry {
    pub timestamp: Option<i64>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub horizontal_accuracy: Option<f64>,
    pub altitude: Option<f64>,
    pub velocity: Option<f64>,
    pub heading: Option<f64>,
    pub source: Option<String>,
    pub application: Option<String>,
}

impl Default for LocationParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for LocationParser {
    fn name(&self) -> &str {
        "iOS Location"
    }

    fn artifact_type(&self) -> &str {
        "location"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["consolidated", "locationd", "cellular"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.len() > 0 {
            let entry = LocationEntry {
                timestamp: None,
                latitude: None,
                longitude: None,
                horizontal_accuracy: None,
                altitude: None,
                velocity: None,
                heading: None,
                source: Some("consolidated.db".to_string()),
                application: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "location".to_string(),
                description: "iOS location data".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

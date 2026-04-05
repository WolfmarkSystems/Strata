use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct HealthParser;

impl HealthParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthEntry {
    pub record_type: Option<String>,
    pub value: Option<f64>,
    pub unit: Option<String>,
    pub start_date: Option<i64>,
    pub end_date: Option<i64>,
    pub source_name: Option<String>,
    pub device_name: Option<String>,
}

impl Default for HealthParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for HealthParser {
    fn name(&self) -> &str {
        "iOS Health"
    }

    fn artifact_type(&self) -> &str {
        "health"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["health", "healthdb", "healthkit"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = HealthEntry {
                record_type: Some("health data".to_string()),
                value: None,
                unit: None,
                start_date: None,
                end_date: None,
                source_name: None,
                device_name: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "health".to_string(),
                description: "iOS Health data".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

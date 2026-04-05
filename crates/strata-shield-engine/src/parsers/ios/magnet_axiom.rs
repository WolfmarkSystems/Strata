use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct AxiomParser;

impl AxiomParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AxiomArtifact {
    pub artifact_type: String,
    pub source: String,
    pub path: String,
    pub name: Option<String>,
    pub size: i64,
    pub created: Option<i64>,
    pub modified: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AxiomCaseInfo {
    pub case_name: String,
    pub case_id: Option<String>,
    pub examiner: Option<String>,
    pub created_date: Option<i64>,
    pub evidence_count: i32,
    pub artifact_count: i32,
}

impl Default for AxiomParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for AxiomParser {
    fn name(&self) -> &str {
        "Magnet AXIOM"
    }

    fn artifact_type(&self) -> &str {
        "phone_acquisition"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["magnet", "axiom", ".axiuiex"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.len() > 0 {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "phone_acquisition".to_string(),
                description: "Magnet AXIOM artifact".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "size": data.len(),
                }),
            });
        }

        Ok(artifacts)
    }
}

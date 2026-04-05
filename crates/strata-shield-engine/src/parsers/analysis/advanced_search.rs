use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct AdvancedSearchParser;

impl AdvancedSearchParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResult {
    pub query: Option<String>,
    pub result_type: Option<String>,
    pub matched_content: Option<String>,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub match_start: Option<i32>,
    pub match_end: Option<i32>,
    pub confidence: f32,
    pub search_method: Option<String>,
    pub fuzzy_distance: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchQuery {
    pub query_string: Option<String>,
    pub query_type: Option<String>,
    pub is_regex: bool,
    pub is_case_sensitive: bool,
    pub is_fuzzy: bool,
    pub fuzzy_threshold: Option<f32>,
    pub file_types: Vec<String>,
    pub date_from: Option<i64>,
    pub date_to: Option<i64>,
    pub min_size: Option<i64>,
    pub max_size: Option<i64>,
}

impl Default for AdvancedSearchParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for AdvancedSearchParser {
    fn name(&self) -> &str {
        "Advanced Search"
    }

    fn artifact_type(&self) -> &str {
        "search"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["*"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.len() > 0 {
            let content = String::from_utf8_lossy(data);
            let preview = if content.len() > 200 {
                format!("{}...", &content[..200])
            } else {
                content.to_string()
            };

            let result = SearchResult {
                query: None,
                result_type: Some("content_match".to_string()),
                matched_content: Some(preview),
                file_path: Some(path.to_string_lossy().to_string()),
                line_number: None,
                match_start: None,
                match_end: None,
                confidence: 1.0,
                search_method: Some("full-text search".to_string()),
                fuzzy_distance: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "search".to_string(),
                description: "Advanced search result".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&result).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

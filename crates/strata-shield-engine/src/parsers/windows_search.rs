use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct WindowsSearchParser;

impl WindowsSearchParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchIndexEntry {
    pub document_id: Option<i64>,
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub keywords: Vec<String>,
    pub modified_time: Option<i64>,
    pub created_time: Option<i64>,
    pub accessed_time: Option<i64>,
    pub size: i64,
    pub content_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchHistoryEntry {
    pub query: String,
    pub timestamp: Option<i64>,
    pub user: Option<String>,
    pub search_count: i32,
}

impl Default for WindowsSearchParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for WindowsSearchParser {
    fn name(&self) -> &str {
        "Windows Search"
    }

    fn artifact_type(&self) -> &str {
        "search"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "windows search",
            "searchindexer",
            "searchdb",
            ".edb",
            "search-ms",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_string();

        if data.len() > 0 {
            let entry = SearchIndexEntry {
                document_id: None,
                file_path: Some(path_str.clone()),
                file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                title: None,
                description: None,
                keywords: vec![],
                modified_time: None,
                created_time: None,
                accessed_time: None,
                size: data.len() as i64,
                content_type: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "search".to_string(),
                description: "Windows Search Index entry".to_string(),
                source_path: path_str,
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

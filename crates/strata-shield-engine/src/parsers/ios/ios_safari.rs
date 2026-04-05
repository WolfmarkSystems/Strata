use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct IosSafariParser;

impl IosSafariParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IosSafariHistoryEntry {
    pub url: Option<String>,
    pub title: Option<String>,
    pub visit_time: Option<i64>,
    pub visit_count: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IosSafariBookmarkEntry {
    pub url: Option<String>,
    pub title: Option<String>,
    pub bookmark_folder: Option<String>,
}

impl Default for IosSafariParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosSafariParser {
    fn name(&self) -> &str {
        "iOS Safari"
    }

    fn artifact_type(&self) -> &str {
        "browser"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["safari", "history.db", "bookmarks.db"]
    }

    fn parse_file(&self, path: &Path, _data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let entry = IosSafariHistoryEntry {
            url: Some(path.to_string_lossy().to_string()),
            title: Some("iOS Safari data".to_string()),
            visit_time: None,
            visit_count: 0,
        };

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "browser".to_string(),
            description: "iOS Safari history".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}

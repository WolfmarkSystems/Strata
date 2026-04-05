use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct MacosAliasBookmarkParser;

impl MacosAliasBookmarkParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AliasBookmarkEntry {
    pub resolved_path: Option<String>,
    pub resolved_url: Option<String>,
    pub source_type: Option<String>,
}

impl Default for MacosAliasBookmarkParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosAliasBookmarkParser {
    fn name(&self) -> &str {
        "macOS Alias/BookmarkData"
    }

    fn artifact_type(&self) -> &str {
        "macos_alias_bookmark"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            ".alias",
            ".webloc",
            "bookmark",
            "bookmarkdata",
            ".sfl",
            ".sfl2",
            ".btm",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let text = String::from_utf8_lossy(data);
        let path_re =
            Regex::new(r"/(?:Users|Volumes|private|Applications|System)/[A-Za-z0-9_\-./ ]+")
                .map_err(|e| ParserError::Parse(e.to_string()))?;
        let url_re = Regex::new(r"https?://[A-Za-z0-9\._~:/?#\[\]@!$&'()*+,;=%\-]+")
            .map_err(|e| ParserError::Parse(e.to_string()))?;

        for m in path_re.find_iter(&text).take(2000) {
            let entry = AliasBookmarkEntry {
                resolved_path: Some(m.as_str().to_string()),
                resolved_url: None,
                source_type: Some("bookmark_path".to_string()),
            };
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "macos_alias_bookmark".to_string(),
                description: "Alias/Bookmark resolved path".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }

        for m in url_re.find_iter(&text).take(2000) {
            let entry = AliasBookmarkEntry {
                resolved_path: None,
                resolved_url: Some(m.as_str().to_string()),
                source_type: Some("bookmark_url".to_string()),
            };
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "macos_alias_bookmark".to_string(),
                description: "Alias/Bookmark resolved URL".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

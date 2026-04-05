use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct SpotlightCarver;

impl SpotlightCarver {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpotlightSnippet {
    pub content: String,
    pub original_file: Option<String>,
}

impl Default for SpotlightCarver {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SpotlightCarver {
    fn name(&self) -> &str {
        "Spotlight Snippet Carver"
    }

    fn artifact_type(&self) -> &str {
        "content_recovery"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".index", ".spotlight-v100", "8db"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        // Spotlight .index files contain text fragments (snippets) of indexed files
        // We scan for human-readable strings within the binary blob
        for chunk in data.chunks(4096).take(1000) {
             let text = String::from_utf8_lossy(chunk);
             for word in text.split_whitespace() {
                  if word.len() > 10 && word.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '@') {
                       // Found a string that looks like an email or a relevant fragment
                       artifacts.push(ParsedArtifact {
                            timestamp: None,
                            artifact_type: "content_recovery".to_string(),
                            description: format!("Spotlight Recovered Snippet: {}", word),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::json!({ "snippet": word }),
                       });
                  }
             }
             if artifacts.len() > 500 { break; }
        }

        Ok(artifacts)
    }
}

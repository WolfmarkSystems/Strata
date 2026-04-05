use regex::Regex;
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct MacosFseventsParser;

impl MacosFseventsParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosFseventsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosFseventsParser {
    fn name(&self) -> &str {
        "macOS FSEvents"
    }

    fn artifact_type(&self) -> &str {
        "macos_fsevents"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".fseventsd", "fseventsd"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        let _ = strata_core::parsers::macos::fsevents_binary::parse_fsevents_binary(
            path,
            data,
            &mut artifacts,
        );
        if !artifacts.is_empty() {
            return Ok(artifacts);
        }

        let text = String::from_utf8_lossy(data);
        for line in text.lines().take(10000) {
            let trimmed = line.trim();
            if !(trimmed.contains('/') || trimmed.contains("rename") || trimmed.contains("delete"))
            {
                continue;
            }
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "macos_fsevents".to_string(),
                description: "macOS FSEvents record".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "record": trimmed,
                    "source": "fsevents_text"
                }),
            });
        }

        // Deep carving pass: recover path-like strings from binary/slack fragments.
        let path_re = Regex::new(
            r"/(?:Users|Volumes|private|Applications|System|Library)/[A-Za-z0-9_\-./ ]+",
        )
        .map_err(|e| ParserError::Parse(e.to_string()))?;
        for m in path_re.find_iter(&text).take(10000) {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "macos_fsevents".to_string(),
                description: "macOS FSEvents carved path".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "carved_path": m.as_str(),
                    "source": "binary_carve"
                }),
            });
        }

        Ok(artifacts)
    }
}

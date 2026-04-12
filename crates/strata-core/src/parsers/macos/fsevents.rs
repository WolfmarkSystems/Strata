use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use regex::Regex;
use std::path::Path;

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

        let _ = crate::parsers::macos::fsevents_binary::parse_fsevents_binary(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_text_with_path_lines() {
        let text = "/Users/test/Documents/secret.pdf renamed\n/Applications/Safari.app delete\n";
        let parser = MacosFseventsParser::new();
        let arts = parser.parse_file(Path::new(".fseventsd/0001"), text.as_bytes()).unwrap();
        assert!(arts.iter().any(|a| {
            a.json_data.get("record").and_then(|v| v.as_str()).unwrap_or("").contains("secret.pdf")
        }));
    }

    #[test]
    fn carves_paths_from_binary_data() {
        let mut data = Vec::new();
        data.extend_from_slice(b"junk junk /Users/victim/Desktop/evidence.doc more junk /System/Library/thing ");
        let parser = MacosFseventsParser::new();
        let arts = parser.parse_file(Path::new(".fseventsd/0002"), &data).unwrap();
        let carved: Vec<_> = arts.iter().filter(|a| a.description.contains("carved")).collect();
        assert!(!carved.is_empty());
    }

    #[test]
    fn empty_data_returns_empty() {
        let parser = MacosFseventsParser::new();
        let arts = parser.parse_file(Path::new(".fseventsd/0003"), b"").unwrap();
        assert!(arts.is_empty());
    }

    #[test]
    fn target_patterns_include_fseventsd() {
        let parser = MacosFseventsParser::new();
        let patterns = parser.target_patterns();
        assert!(patterns.contains(&".fseventsd"));
    }
}

use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct SafariCacheParser;

impl SafariCacheParser {
    pub fn new() -> Self {
        Self
    }
}

pub fn carve_media(data: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    // JPEG: FF D8 FF
    if data.windows(3).any(|w| w == b"\xFF\xD8\xFF") {
        found.push("JPEG Image Fragment".to_string());
    }
    // PNG: 89 50 4E 47
    if data.windows(4).any(|w| w == b"\x89PNG") {
        found.push("PNG Image Fragment".to_string());
    }
    found
}

impl Default for SafariCacheParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SafariCacheParser {
    fn name(&self) -> &str {
        "Safari Cache Recovery"
    }

    fn artifact_type(&self) -> &str {
        "browser_cache"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["fsCachedData", "Cache.db"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.contains("fscacheddata") {
            let media = carve_media(data);
            for m in media {
                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "browser_cache".to_string(),
                    description: format!("Recovered Safari Cache: {}", m),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::json!({ "type": m, "size": data.len() }),
                });
            }
        }

        Ok(artifacts)
    }
}

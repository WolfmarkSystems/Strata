use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde_json::json;
use std::path::Path;

pub struct CheckrainFfsParser {}

impl CheckrainFfsParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for CheckrainFfsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for CheckrainFfsParser {
    fn name(&self) -> &str {
        "iOS Full File System (FFS)"
    }

    fn artifact_type(&self) -> &str {
        "ios_ffs_metadata"
    }

    fn target_patterns(&self) -> Vec<&str> {
        // Target specific directories or manifests that indicate FFS instead of backup
        vec!["fstab", ".fseventsd", "private"]
    }

    fn parse_file(&self, path: &Path, _data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let py_path = path.to_string_lossy().to_string();

        let mut artifacts = Vec::new();
        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: self.artifact_type().to_string(),
            description: "Detected iOS FFS Extraction Component".to_string(),
            source_path: py_path,
            json_data: json!({
                "extraction_type": "Full File System",
                "jailbreak_artifact_likely": true
            }),
        });

        Ok(artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffs_parser() {
        let parser = CheckrainFfsParser::new();
        let artifacts = parser
            .parse_file(Path::new("private/var/root/.bash_history"), b"")
            .unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].json_data.get("extraction_type").unwrap(),
            "Full File System"
        );
    }
}

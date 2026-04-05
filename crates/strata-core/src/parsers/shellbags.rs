use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use std::path::Path;

pub struct ShellbagsParser;

impl Default for ShellbagsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ShellbagsParser {
    pub fn new() -> Self {
        Self
    }
}

impl ArtifactParser for ShellbagsParser {
    fn name(&self) -> &str {
        "Shellbags Parser"
    }

    fn artifact_type(&self) -> &str {
        "shellbags"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["NTUSER.DAT", "USRCLASS.DAT"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "shellbags".to_string(),
            description: format!("Shellbags source: {}", filename),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "source_file": filename,
                "size_bytes": data.len(),
                "note": "Shellbags present in user registry hive. Full parsing extracts folder paths."
            }),
        });

        Ok(artifacts)
    }
}

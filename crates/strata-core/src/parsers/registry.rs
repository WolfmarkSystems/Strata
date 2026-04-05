use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use std::path::Path;

pub struct RegistryParser;

impl Default for RegistryParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryParser {
    pub fn new() -> Self {
        Self
    }
}

impl ArtifactParser for RegistryParser {
    fn name(&self) -> &str {
        "Windows Registry Parser"
    }

    fn artifact_type(&self) -> &str {
        "registry"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "SYSTEM",
            "SOFTWARE",
            "SECURITY",
            "SAM",
            "USRCLASS.DAT",
            "NTUSER.DAT",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let hive_name = path
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| filename.clone());

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "registry".to_string(),
            description: format!("Registry hive: {}", hive_name),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "hive": hive_name,
                "filename": filename,
                "size_bytes": data.len(),
                "note": "Registry hive file parsed. Full key/value extraction requires winreg integration."
            }),
        });

        Ok(artifacts)
    }
}

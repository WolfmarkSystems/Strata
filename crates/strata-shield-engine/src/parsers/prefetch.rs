use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use std::path::Path;

pub struct PrefetchParser;

impl PrefetchParser {
    pub fn new() -> Self {
        Self
    }
}

impl ArtifactParser for PrefetchParser {
    fn name(&self) -> &str {
        "Windows Prefetch Parser"
    }

    fn artifact_type(&self) -> &str {
        "prefetch"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".pf"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let exe_name = filename
            .trim_end_matches(".pf")
            .trim_end_matches("-PF")
            .to_string();

        let timestamp = if data.len() >= 4 {
            if let Ok(_timestamp) = u32::try_from(data.len()) {
                None
            } else {
                None
            }
        } else {
            None
        };

        artifacts.push(ParsedArtifact {
            timestamp,
            artifact_type: "prefetch".to_string(),
            description: format!("Prefetch: {} executed", exe_name),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "executable": exe_name,
                "filename": filename,
                "size_bytes": data.len(),
                "note": "Prefetch file. Run count and timestamps require full parser."
            }),
        });

        Ok(artifacts)
    }
}

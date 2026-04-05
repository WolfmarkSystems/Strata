use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use std::path::Path;

pub struct EvtxParser;

impl EvtxParser {
    pub fn new() -> Self {
        Self
    }
}

impl ArtifactParser for EvtxParser {
    fn name(&self) -> &str {
        "Windows EVTX Parser"
    }

    fn artifact_type(&self) -> &str {
        "eventlog"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".evtx"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let log_name = filename.trim_end_matches(".evtx").to_string();

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "eventlog".to_string(),
            description: format!("Event Log: {}", log_name),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "log_name": log_name,
                "filename": filename,
                "size_bytes": data.len(),
                "note": "EVTX file detected. Full event extraction using evtx crate available."
            }),
        });

        Ok(artifacts)
    }
}

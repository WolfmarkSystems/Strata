use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::parse_plist_data;

use std::path::Path;

pub struct MacosNetworkingAudit;

impl MacosNetworkingAudit {
    pub fn new() -> Self {
        Self
    }
}

impl ArtifactParser for MacosNetworkingAudit {
    fn name(&self) -> &str {
        "macOS Networking Audit"
    }

    fn artifact_type(&self) -> &str {
        "network_config"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["com.apple.sharing.firewall.plist", "com.apple.Sharing.plist"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        if let Ok(plist_val) = parse_plist_data(data) {
             artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "network_config".to_string(),
                description: "Extended Networking/Sharing Configuration Found".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&plist_val).unwrap_or_default(),
             });
        }
        Ok(artifacts)
    }
}

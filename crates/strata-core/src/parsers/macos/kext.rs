use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::{get_string_from_plist, parse_plist_data};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosKextParser;

impl MacosKextParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KextInfo {
    pub name: String,
    pub bundle_id: String,
    pub version: String,
    pub is_apple: bool,
    pub path: String,
}

impl Default for MacosKextParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosKextParser {
    fn name(&self) -> &str {
        "macOS Kext Audit"
    }

    fn artifact_type(&self) -> &str {
        "persistence"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Info.plist", "Extensions"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        // We only care about Info.plist inside a .kext or .bundle directory in Extensions
        if (path_str.contains("/extensions/") || path_str.contains("/driverextensions/"))
            && path_str.ends_with("info.plist")
        {
            if let Ok(plist_val) = parse_plist_data(data) {
                let bundle_id = get_string_from_plist(&plist_val, "CFBundleIdentifier")
                    .unwrap_or_else(|| "unknown".to_string());
                let name = get_string_from_plist(&plist_val, "CFBundleName")
                    .unwrap_or_else(|| "unknown".to_string());
                let version = get_string_from_plist(&plist_val, "CFBundleShortVersionString")
                    .unwrap_or_else(|| "0.0".to_string());

                let is_apple = bundle_id.starts_with("com.apple.");

                let info = KextInfo {
                    name,
                    bundle_id,
                    version,
                    is_apple,
                    path: path.to_string_lossy().to_string(),
                };

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "persistence".to_string(),
                    description: format!(
                        "Kernel Extension Identified: {} ({})",
                        info.name, info.bundle_id
                    ),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(info).unwrap_or_default(),
                });
            }
        }

        Ok(artifacts)
    }
}

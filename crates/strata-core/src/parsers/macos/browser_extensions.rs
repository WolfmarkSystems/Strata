use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct BrowserExtensionParser;

impl BrowserExtensionParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserExtension {
    pub name: String,
    pub id: String,
    pub version: String,
    pub description: Option<String>,
    pub browser: String,
    pub permissions: Vec<String>,
}

impl Default for BrowserExtensionParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for BrowserExtensionParser {
    fn name(&self) -> &str {
        "Browser Extensions"
    }

    fn artifact_type(&self) -> &str {
        "browser_extension"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["manifest.json", "Extensions"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.ends_with("manifest.json") {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
                let name = json
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let version = json
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0.0.0")
                    .to_string();
                let id = path
                    .parent()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                let browser = if path_str.contains("google/chrome") {
                    "Chrome"
                } else if path_str.contains("microsoft edge") {
                    "Edge"
                } else if path_str.contains("brave") {
                    "Brave"
                } else {
                    "Chromium"
                };

                let mut permissions = Vec::new();
                if let Some(p_list) = json.get("permissions").and_then(|v| v.as_array()) {
                    for p in p_list {
                        if let Some(s) = p.as_str() {
                            permissions.push(s.to_string());
                        }
                    }
                }

                let ext = BrowserExtension {
                    name: name.clone(),
                    id,
                    version,
                    description: json
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    browser: browser.to_string(),
                    permissions,
                };

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "browser_extension".to_string(),
                    description: format!("{} Extension: {}", browser, name),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(ext).unwrap_or_default(),
                });
            }
        }

        Ok(artifacts)
    }
}

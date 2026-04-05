use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::{parse_plist_data, get_string_from_plist};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosNetworkShareParser;

impl MacosNetworkShareParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkShare {
    pub url: String,
    pub name: Option<String>,
    pub last_used: Option<i64>,
}

impl Default for MacosNetworkShareParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosNetworkShareParser {
    fn name(&self) -> &str {
        "Network Share History"
    }

    fn artifact_type(&self) -> &str {
        "network_config"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["com.apple.sidebarlists.plist", "com.apple.AppleShareClient.plist"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let plist_val = parse_plist_data(data)?;
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.contains("sidebarlists") {
             if let Some(favorites) = plist_val.as_dictionary().and_then(|d| d.get("favorites")).and_then(|v| v.as_dictionary()).and_then(|v| v.get("Items")).and_then(|v| v.as_array()) {
                for item in favorites {
                     let name = get_string_from_plist(item, "Name").unwrap_or_else(|| "unknown".to_string());
                     if let Some(url) = get_string_from_plist(item, "URL") {
                         artifacts.push(ParsedArtifact {
                            timestamp: None,
                            artifact_type: "network_config".to_string(),
                            description: format!("Network Share Favorite: {} ({})", name, url),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::to_value(NetworkShare {
                                url,
                                name: Some(name),
                                last_used: None,
                            }).unwrap_or_default(),
                         });
                     }
                }
             }
        }

        Ok(artifacts)
    }
}

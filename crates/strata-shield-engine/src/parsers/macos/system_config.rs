use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::{parse_plist_data, get_string_from_plist, get_bool_from_plist};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosSystemConfigParser;

impl MacosSystemConfigParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SharingConfig {
    pub service_name: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginItem {
    pub name: String,
    pub path: Option<String>,
}

impl Default for MacosSystemConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosSystemConfigParser {
    fn name(&self) -> &str {
        "macOS System Config"
    }

    fn artifact_type(&self) -> &str {
        "system_config"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["com.apple.sharingd.plist", "com.apple.loginwindow.plist", "com.apple.loginitems.plist"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let plist_val = parse_plist_data(data)?;
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.contains("sharingd") {
            let entries = [
                ("AirDrop", "AirDropEnabled"),
                ("File Sharing", "DiscoverableMode"),
            ];
            for (name, key) in entries {
                 let val = get_bool_from_plist(&plist_val, key).unwrap_or(false);
                 artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "system_config".to_string(),
                    description: format!("Sharing Service: {} is {}", name, if val { "Enabled" } else { "Disabled" }),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(SharingConfig {
                        service_name: name.to_string(),
                        enabled: val,
                    }).unwrap_or_default(),
                 });
            }
        } else if path_str.contains("loginitems") {
             if let Some(items) = plist_val.as_dictionary().and_then(|d| d.get("SessionItems")).and_then(|v| v.as_dictionary()).and_then(|v| v.get("CustomListItems")).and_then(|v| v.as_array()) {
                for item in items {
                    let name = get_string_from_plist(item, "Name").unwrap_or_else(|| "unknown".to_string());
                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "system_config".to_string(),
                        description: format!("Login Item: {}", name),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(LoginItem {
                            name,
                            path: None,
                        }).unwrap_or_default(),
                    });
                }
             }
        }

        Ok(artifacts)
    }
}

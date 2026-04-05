use crate::plist_utils::{get_string_from_plist, parse_plist_data};
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct MacosRecentItemsParser;

impl MacosRecentItemsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecentItem {
    pub name: String,
    pub path: Option<String>,
    pub last_opened: Option<i64>,
}

impl Default for MacosRecentItemsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosRecentItemsParser {
    fn name(&self) -> &str {
        "macOS Recent Items"
    }

    fn artifact_type(&self) -> &str {
        "user_activity"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["com.apple.recentitems.plist", ".sfl2", ".sfl3"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.ends_with(".plist") {
            let plist_val = parse_plist_data(data)?;
            if let Some(recent_apps) = plist_val
                .as_dictionary()
                .and_then(|d| d.get("RecentApplications"))
                .and_then(|v| v.as_dictionary())
                .and_then(|v| v.get("CustomListItems"))
                .and_then(|v| v.as_array())
            {
                for item in recent_apps {
                    let name = get_string_from_plist(item, "Name")
                        .unwrap_or_else(|| "unknown".to_string());
                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "user_activity".to_string(),
                        description: format!("Recent Application: {}", name),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(RecentItem {
                            name,
                            path: None,
                            last_opened: None,
                        })
                        .unwrap_or_default(),
                    });
                }
            }
        } else if path_str.ends_with(".sfl2") || path_str.ends_with(".sfl3") {
            // SFL files are basically KeyedArchiver serialized plists.
            // Our plist crate might handle them if they are in standard binary format.
            if let Ok(plist_val) = parse_plist_data(data) {
                if let Some(items) = plist_val
                    .as_dictionary()
                    .and_then(|d| d.get("items"))
                    .and_then(|v| v.as_array())
                {
                    for item in items {
                        let name = get_string_from_plist(item, "name")
                            .unwrap_or_else(|| "unknown".to_string());
                        artifacts.push(ParsedArtifact {
                            timestamp: None,
                            artifact_type: "user_activity".to_string(),
                            description: format!("Shared File List Item: {}", name),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::to_value(RecentItem {
                                name,
                                path: None,
                                last_opened: None,
                            })
                            .unwrap_or_default(),
                        });
                    }
                }
            }
        }

        Ok(artifacts)
    }
}

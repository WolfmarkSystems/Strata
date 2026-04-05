use serde::{Deserialize, Serialize};
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct JumpListParser;

impl Default for JumpListParser {
    fn default() -> Self {
        Self::new()
    }
}

impl JumpListParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JumpListEntry {
    pub entry_type: String,
    pub target_path: Option<String>,
    pub arguments: Option<String>,
    pub working_directory: Option<String>,
    pub icon_location: Option<String>,
    pub timestamp: Option<i64>,
    pub app_id: Option<String>,
    pub shell_item: Option<String>,
}

impl ArtifactParser for JumpListParser {
    fn name(&self) -> &str {
        "Windows Jump List Parser"
    }

    fn artifact_type(&self) -> &str {
        "jumplist"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            ".automaticDestinations",
            ".customDestinations",
            "automaticDestinations-ms",
            "customDestinations-ms",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if data.len() < 4 {
            return Ok(artifacts);
        }

        if data.len() >= 4 && data[0..4] == [0x4D, 0x54, 0x58, 0x1C] {
            artifacts.extend(self.parse_automatic_destinations(path, data)?);
        } else if data.len() >= 4 && data[0..4] == [0x55, 0x6E, 0x6B, 0x00] {
            artifacts.extend(self.parse_custom_destinations(path, data)?);
        }

        if artifacts.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "jumplist".to_string(),
                description: format!("Jump List file: {}", filename),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "filename": filename,
                    "size_bytes": data.len(),
                    "note": "Jump List file detected. Full parsing requires shell item structure."
                }),
            });
        }

        Ok(artifacts)
    }
}

impl JumpListParser {
    fn parse_automatic_destinations(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let mut offset = 0x4C;

        while offset + 0x60 <= data.len() {
            let entry_data = &data[offset..offset.min(data.len())];

            if entry_data.len() < 16 {
                break;
            }

            let target_offset = u16::from_le_bytes([entry_data[0], entry_data[1]]) as usize;
            let target_size = u16::from_le_bytes([entry_data[2], entry_data[3]]) as usize;

            if target_offset > 0 && target_offset + target_size <= data.len() {
                let shell_item_data =
                    &data[target_offset..(target_offset + target_size).min(data.len())];

                let entry = JumpListEntry {
                    entry_type: "automaticDestination".to_string(),
                    target_path: self.parse_shell_item(shell_item_data),
                    arguments: None,
                    working_directory: None,
                    icon_location: None,
                    timestamp: None,
                    app_id: None,
                    shell_item: Some(format!(
                        "{:02x?}",
                        &shell_item_data[..shell_item_data.len().min(20)]
                    )),
                };

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "jumplist_entry".to_string(),
                    description: format!("Jump List: {:?}", entry.target_path),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(entry).unwrap_or_default(),
                });
            }

            offset += 0x60;

            if offset >= data.len() || data[offset..offset.min(4)].iter().all(|&b| b == 0) {
                break;
            }
        }

        Ok(artifacts)
    }

    fn parse_custom_destinations(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let mut offset = 0x20;

        while offset + 0x40 <= data.len() {
            let entry_data = &data[offset..offset.min(data.len())];

            if entry_data.len() < 8 {
                break;
            }

            let link_offset =
                u32::from_le_bytes([entry_data[0], entry_data[1], entry_data[2], entry_data[3]])
                    as usize;

            if link_offset > 0 && link_offset + 0x4 <= data.len() {
                let entry = JumpListEntry {
                    entry_type: "customDestination".to_string(),
                    target_path: None,
                    arguments: None,
                    working_directory: None,
                    icon_location: None,
                    timestamp: None,
                    app_id: None,
                    shell_item: Some(format!("Link at offset: {}", link_offset)),
                };

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "jumplist_entry".to_string(),
                    description: "Custom Jump List entry".to_string(),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(entry).unwrap_or_default(),
                });
            }

            offset += 0x40;
        }

        Ok(artifacts)
    }

    fn parse_shell_item(&self, data: &[u8]) -> Option<String> {
        if data.len() < 4 {
            return None;
        }

        let size = data[0] as usize;
        if size < 4 || size > data.len() {
            return None;
        }

        let item_type = data[2];

        match item_type {
            0x1F => Some("Root".to_string()),
            0x2F => {
                if size > 3 {
                    let name_len = size - 3;
                    let name_data = &data[3..(3 + name_len).min(data.len())];
                    String::from_utf8_lossy(name_data)
                        .trim_end_matches('\0')
                        .to_string()
                        .into()
                } else {
                    None
                }
            }
            0x31 | 0x32 | 0x35 | 0x36 => {
                if size > 3 {
                    let name_len = size - 3;
                    let name_data = &data[3..(3 + name_len).min(data.len())];
                    Some(
                        String::from_utf8_lossy(name_data)
                            .trim_end_matches('\0')
                            .to_string(),
                    )
                } else {
                    None
                }
            }
            0x00 => None,
            _ => Some(format!("Type: 0x{:02x}", item_type)),
        }
    }
}

use std::path::Path;

use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct RecentDocsParser;

impl Default for RecentDocsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RecentDocsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecentDocEntry {
    pub name: String,
    pub extension: Option<String>,
    pub target_guid: Option<String>,
    pub mru_index: Option<u32>,
}

impl ArtifactParser for RecentDocsParser {
    fn name(&self) -> &str {
        "Windows RecentDocs Parser"
    }

    fn artifact_type(&self) -> &str {
        "recentdocs"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Recent"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if filename.ends_with(".lnk") {
            let doc_name = filename.trim_end_matches(".lnk").to_string();

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "recentdoc".to_string(),
                description: format!("Recent document accessed: {}", doc_name),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "name": doc_name,
                    "extension": Path::new(&doc_name)
                        .extension()
                        .map(|e| e.to_string_lossy().to_string()),
                    "mru_index": Option::<u32>::None,
                }),
            });
        } else if data.len() >= 4 && data[0..4] == [0x00, 0x00, 0x00, 0x00] {
            if let Ok(entries) = self.parse_shell_item_folder(path, data) {
                for entry in entries {
                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "recentdoc".to_string(),
                        description: format!("Recent document: {}", entry.name),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }
            }
        } else if data.len() >= 4 && data[0] == 0x03 && data[1] == 0x00 {
            if let Ok(entries) = self.parse_mru_list(path, data) {
                for entry in entries {
                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "recentdoc".to_string(),
                        description: format!("Recent document: {}", entry.name),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }
            }
        }

        if artifacts.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "recentdocs".to_string(),
                description: format!("RecentDocs: {}", filename),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "filename": filename,
                    "size_bytes": data.len(),
                    "note": "RecentDocs file detected"
                }),
            });
        }

        Ok(artifacts)
    }
}

impl RecentDocsParser {
    fn parse_shell_item_folder(
        &self,
        _path: &Path,
        data: &[u8],
    ) -> Result<Vec<RecentDocEntry>, ParserError> {
        let mut entries = Vec::new();

        if data.len() < 4 {
            return Ok(entries);
        }

        let folder_size = u16::from_le_bytes([data[0], data[1]]);

        if folder_size < 4 || folder_size as usize > data.len() {
            return Ok(entries);
        }

        let mut offset = 4;

        while offset + 2 < data.len() {
            let entry_size = data[offset] as usize;

            if entry_size == 0 {
                break;
            }

            if offset + entry_size > data.len() {
                break;
            }

            let entry_data = &data[offset..offset + entry_size];

            if entry_data.len() >= 4 {
                let item_type = entry_data[2];

                match item_type {
                    0x1F => {}
                    0x2F => {
                        if entry_data.len() > 3 {
                            let name_len = entry_data.len() - 3;
                            let name_data = &entry_data[3..(3 + name_len).min(entry_data.len())];
                            if let Ok(name) = String::from_utf8(name_data.to_vec()) {
                                let name = name.trim_end_matches('\0').to_string();
                                if !name.is_empty() {
                                    entries.push(RecentDocEntry {
                                        name: name.clone(),
                                        extension: Path::new(&name)
                                            .extension()
                                            .map(|e| e.to_string_lossy().to_string()),
                                        target_guid: None,
                                        mru_index: None,
                                    });
                                }
                            }
                        }
                    }
                    0x31 | 0x32 | 0x35 | 0x36 => {
                        if entry_data.len() > 3 {
                            let name_len = entry_data.len() - 3;
                            let name_data = &entry_data[3..(3 + name_len).min(entry_data.len())];
                            if let Ok(name) = String::from_utf8(name_data.to_vec()) {
                                let name = name.trim_end_matches('\0').to_string();
                                if !name.is_empty() {
                                    entries.push(RecentDocEntry {
                                        name: name.clone(),
                                        extension: Path::new(&name)
                                            .extension()
                                            .map(|e| e.to_string_lossy().to_string()),
                                        target_guid: None,
                                        mru_index: None,
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            offset += entry_size;
        }

        Ok(entries)
    }

    fn parse_mru_list(
        &self,
        _path: &Path,
        data: &[u8],
    ) -> Result<Vec<RecentDocEntry>, ParserError> {
        let mut entries = Vec::new();

        if data.len() < 4 {
            return Ok(entries);
        }

        let entry_count = data[3];

        let mut offset = 4;

        for i in 0..entry_count {
            if offset + 2 > data.len() {
                break;
            }

            let entry_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;

            if entry_size < 4 || offset + entry_size > data.len() {
                break;
            }

            let entry_data = &data[offset + 2..offset + entry_size];

            if entry_data.len() >= 2 {
                let name_len = entry_data[0] as usize;

                if name_len > 0 && name_len * 2 + 2 <= entry_data.len() {
                    let name_u16: Vec<u16> = entry_data
                        [2..(2 + name_len * 2).min(entry_data.len())]
                        .chunks(2)
                        .filter_map(|c| {
                            if c.len() == 2 {
                                Some(u16::from_le_bytes([c[0], c[1]]))
                            } else {
                                None
                            }
                        })
                        .collect();

                    let name = String::from_utf16_lossy(&name_u16);
                    if !name.is_empty() {
                        entries.push(RecentDocEntry {
                            name,
                            extension: None,
                            target_guid: None,
                            mru_index: Some(i as u32),
                        });
                    }
                }
            }

            offset += entry_size;
        }

        Ok(entries)
    }
}

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct AmcacheParser;

impl AmcacheParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AmcacheEntry {
    pub program_id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_time: Option<i64>,
    pub last_modified: Option<i64>,
    pub size: Option<i64>,
    pub path: Option<String>,
    pub sha1: Option<String>,
}

impl ArtifactParser for AmcacheParser {
    fn name(&self) -> &str {
        "Windows Amcache Parser"
    }

    fn artifact_type(&self) -> &str {
        "amcache"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "Amcache.hve",
            "amcache.hve",
            "Amcache.hve.LOG1",
            "amcache.hve.LOG1",
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

        if &data[0..4] == [0xFE, 0x12, 0x34, 0x56] || &data[0..4] == [0xD0, 0xCF, 0x11, 0xE0] {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "amcache".to_string(),
                description: format!("Amcache.hve: {}", filename),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "filename": filename,
                    "format": "Windows Registry HIVE format",
                    "note": "Amcache.hve requires Windows Registry parsing. This contains program execution history."
                }),
            });
        } else {
            let mut offset = 0;
            while offset + 32 <= data.len() {
                let entry_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;

                if entry_size == 0 || entry_size > data.len() - offset {
                    break;
                }

                if offset + entry_size <= data.len() {
                    let entry_data = &data[offset..offset + entry_size];

                    let mut entry = AmcacheEntry {
                        program_id: None,
                        name: None,
                        version: None,
                        publisher: None,
                        install_time: None,
                        last_modified: None,
                        size: None,
                        path: None,
                        sha1: None,
                    };

                    if entry_data.len() > 4 {
                        let num_entries = u16::from_le_bytes([entry_data[2], entry_data[3]]);

                        let mut pos = 4;
                        for _ in 0..num_entries {
                            if pos + 4 > entry_data.len() {
                                break;
                            }

                            let value_type =
                                u16::from_le_bytes([entry_data[pos], entry_data[pos + 1]]);
                            let value_size =
                                u16::from_le_bytes([entry_data[pos + 2], entry_data[pos + 3]])
                                    as usize;
                            pos += 4;

                            if pos + value_size > entry_data.len() {
                                break;
                            }

                            let value_data = &entry_data[pos..pos + value_size];

                            match value_type {
                                0x0001 | 0x0002 => {
                                    entry.name = Some(
                                        String::from_utf8_lossy(value_data)
                                            .trim_end_matches('\0')
                                            .to_string(),
                                    );
                                }
                                0x0003 | 0x0004 => {
                                    entry.version = Some(
                                        String::from_utf8_lossy(value_data)
                                            .trim_end_matches('\0')
                                            .to_string(),
                                    );
                                }
                                0x0005 | 0x0006 => {
                                    entry.publisher = Some(
                                        String::from_utf8_lossy(value_data)
                                            .trim_end_matches('\0')
                                            .to_string(),
                                    );
                                }
                                0x0007 | 0x0008 => {
                                    if value_size >= 8 {
                                        let ts = i64::from_le_bytes([
                                            value_data[0],
                                            value_data[1],
                                            value_data[2],
                                            value_data[3],
                                            value_data[4],
                                            value_data[5],
                                            value_data[6],
                                            value_data[7],
                                        ]);
                                        if ts > 0 {
                                            entry.install_time =
                                                Some((ts - 116444736000000000) / 10000);
                                        }
                                    }
                                }
                                0x0009 | 0x000A => {
                                    if value_size >= 8 {
                                        let ts = i64::from_le_bytes([
                                            value_data[0],
                                            value_data[1],
                                            value_data[2],
                                            value_data[3],
                                            value_data[4],
                                            value_data[5],
                                            value_data[6],
                                            value_data[7],
                                        ]);
                                        if ts > 0 {
                                            entry.last_modified =
                                                Some((ts - 116444736000000000) / 10000);
                                        }
                                    }
                                }
                                0x000B | 0x000C => {
                                    entry.size = Some(i64::from_le_bytes([
                                        value_data[0],
                                        value_data[1],
                                        value_data[2],
                                        value_data[3],
                                        value_data[4],
                                        value_data[5],
                                        value_data[6],
                                        value_data[7],
                                    ]));
                                }
                                0x0015 | 0x0016 => {
                                    entry.path = Some(
                                        String::from_utf8_lossy(value_data)
                                            .trim_end_matches('\0')
                                            .to_string(),
                                    );
                                }
                                0x001A => {
                                    entry.sha1 = Some(format!("{:02x?}", value_data));
                                }
                                _ => {}
                            }

                            pos += value_size;
                            if value_size % 4 != 0 {
                                pos += 4 - (value_size % 4);
                            }
                        }
                    }

                    if entry.name.is_some() || entry.program_id.is_some() {
                        artifacts.push(ParsedArtifact {
                            timestamp: entry.install_time.or(entry.last_modified),
                            artifact_type: "amcache_entry".to_string(),
                            description: format!(
                                "Amcache: {}",
                                entry.name.as_deref().unwrap_or("Unknown program")
                            ),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::to_value(entry).unwrap_or_default(),
                        });
                    }
                }

                offset += entry_size;

                if offset >= data.len() || entry_size == 0 {
                    break;
                }
            }
        }

        if artifacts.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "amcache".to_string(),
                description: format!("Amcache: {}", filename),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "filename": filename,
                    "size_bytes": data.len(),
                    "note": "Amcache.hve file"
                }),
            });
        }

        Ok(artifacts)
    }
}

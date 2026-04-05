use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct RecycleBinParser;

impl Default for RecycleBinParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RecycleBinParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecycleBinEntry {
    pub file_id: Option<String>,
    pub original_path: Option<String>,
    pub deletion_time: Option<i64>,
    pub file_size: Option<i64>,
}

impl ArtifactParser for RecycleBinParser {
    fn name(&self) -> &str {
        "Windows Recycle Bin Parser"
    }

    fn artifact_type(&self) -> &str {
        "recyclebin"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["$I", "$R", "$Recycle.Bin"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if filename.starts_with('$') && (filename.len() == 2 || filename.len() == 3) {
            if data.len() >= 16 {
                let mut entry = RecycleBinEntry {
                    file_id: Some(filename.clone()),
                    original_path: None,
                    deletion_time: None,
                    file_size: None,
                };

                if data.len() >= 24 {
                    let deletion_time = i64::from_le_bytes([
                        data[8], data[9], data[10], data[11], data[12], data[13], data[14],
                        data[15],
                    ]);
                    if deletion_time > 0 {
                        entry.deletion_time = Some((deletion_time - 116444736000000000) / 10000);
                    }
                }

                if data.len() >= 32 {
                    entry.file_size = Some(i64::from_le_bytes([
                        data[24], data[25], data[26], data[27], data[28], data[29], data[30],
                        data[31],
                    ]));
                }

                artifacts.push(ParsedArtifact {
                    timestamp: entry.deletion_time,
                    artifact_type: "recyclebin_entry".to_string(),
                    description: format!("Recycle Bin: {}", filename),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(entry).unwrap_or_default(),
                });
            }
        } else if data.len() >= 4 && data[0..4] == [0x01, 0x00, 0x00, 0x00] {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "recyclebin".to_string(),
                description: format!("Recycle Bin folder: {}", filename),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "filename": filename,
                    "size_bytes": data.len(),
                    "note": "Recycle Bin directory entry"
                }),
            });
        }

        if artifacts.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "recyclebin".to_string(),
                description: format!("Recycle Bin: {}", filename),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "filename": filename,
                    "size_bytes": data.len()
                }),
            });
        }

        Ok(artifacts)
    }
}

pub struct UsnJournalParser;

impl Default for UsnJournalParser {
    fn default() -> Self {
        Self::new()
    }
}

impl UsnJournalParser {
    pub fn new() -> Self {
        Self
    }
}

impl ArtifactParser for UsnJournalParser {
    fn name(&self) -> &str {
        "Windows USN Journal Parser"
    }

    fn artifact_type(&self) -> &str {
        "usnjournal"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["$Extend\\$UsnJrnl", "$UsnJrnl"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut artifacts = Vec::new();
        let mut offset = 0;
        let mut entry_count = 0;

        while offset + 40 <= data.len() && entry_count < 100 {
            let record_size = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;

            if record_size < 40 || record_size > data.len() - offset {
                break;
            }

            let major_version = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
            let minor_version = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);

            if major_version != 2 && major_version != 3 {
                offset += record_size;
                continue;
            }

            let usn = i64::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);

            let timestamp = i64::from_le_bytes([
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
                data[offset + 20],
                data[offset + 21],
                data[offset + 22],
                data[offset + 23],
            ]);

            let reason = u32::from_le_bytes([
                data[offset + 24],
                data[offset + 25],
                data[offset + 26],
                data[offset + 27],
            ]);

            let name_length = u16::from_le_bytes([data[offset + 38], data[offset + 39]]) as usize;

            let name = if name_length > 0 && offset + 40 + name_length <= data.len() {
                let name_u16: Vec<u16> = data[offset + 40..offset + 40 + name_length]
                    .chunks(2)
                    .filter_map(|c| {
                        if c.len() == 2 {
                            Some(u16::from_le_bytes([c[0], c[1]]))
                        } else {
                            None
                        }
                    })
                    .collect();
                Some(
                    String::from_utf16_lossy(&name_u16)
                        .trim_end_matches('\0')
                        .to_string(),
                )
            } else {
                None
            };

            let reason_str = self.decode_reason(reason);

            artifacts.push(ParsedArtifact {
                timestamp: Some((timestamp - 116444736000000000) / 10000),
                artifact_type: "usn_entry".to_string(),
                description: format!(
                    "USN: {} ({})",
                    name.as_deref().unwrap_or("Unknown"),
                    reason_str
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "usn": usn,
                    "timestamp": timestamp,
                    "reason": reason_str,
                    "name": name,
                    "major_version": major_version,
                    "minor_version": minor_version
                }),
            });

            entry_count += 1;
            offset += record_size;
        }

        if artifacts.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "usnjournal".to_string(),
                description: format!("USN Journal: {}", filename),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "filename": filename,
                    "size_bytes": data.len(),
                    "note": "USN Journal file. Use NTFS parser for full extraction."
                }),
            });
        }

        Ok(artifacts)
    }
}

impl UsnJournalParser {
    fn decode_reason(&self, reason: u32) -> String {
        let mut reasons = Vec::new();

        if reason & 0x00000001 != 0 {
            reasons.push("DATA_OVERWRITE");
        }
        if reason & 0x00000002 != 0 {
            reasons.push("DATA_EXTEND");
        }
        if reason & 0x00000004 != 0 {
            reasons.push("DATA_TRUNCATION");
        }
        if reason & 0x00000100 != 0 {
            reasons.push("NAMED_DATA_OVERWRITE");
        }
        if reason & 0x00000200 != 0 {
            reasons.push("NAMED_DATA_EXTEND");
        }
        if reason & 0x00000400 != 0 {
            reasons.push("NAMED_DATA_TRUNCATION");
        }
        if reason & 0x00001000 != 0 {
            reasons.push("FILE_CREATE");
        }
        if reason & 0x00002000 != 0 {
            reasons.push("FILE_DELETE");
        }
        if reason & 0x00004000 != 0 {
            reasons.push("EA_CHANGE");
        }
        if reason & 0x00008000 != 0 {
            reasons.push("SECURITY_CHANGE");
        }
        if reason & 0x00010000 != 0 {
            reasons.push("RENAME_OLD_NAME");
        }
        if reason & 0x00020000 != 0 {
            reasons.push("RENAME_NEW_NAME");
        }
        if reason & 0x00040000 != 0 {
            reasons.push("INDEXABLE_CHANGE");
        }
        if reason & 0x00080000 != 0 {
            reasons.push("BASIC_INFO_CHANGE");
        }
        if reason & 0x00100000 != 0 {
            reasons.push("HARD_LINK_CHANGE");
        }
        if reason & 0x00200000 != 0 {
            reasons.push("COMPRESSION_CHANGE");
        }
        if reason & 0x00400000 != 0 {
            reasons.push("ENCRYPTION_CHANGE");
        }
        if reason & 0x00800000 != 0 {
            reasons.push("OBJECT_ID_CHANGE");
        }
        if reason & 0x01000000 != 0 {
            reasons.push("REPARSE_POINT_CHANGE");
        }
        if reason & 0x02000000 != 0 {
            reasons.push("STREAM_CHANGE");
        }
        if reason & 0x04000000 != 0 {
            reasons.push("TRANSACTED_CHANGE");
        }

        if reasons.is_empty() {
            format!("0x{:08X}", reason)
        } else {
            reasons.join(", ")
        }
    }
}

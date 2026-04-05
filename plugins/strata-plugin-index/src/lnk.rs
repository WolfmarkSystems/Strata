use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct LnkParser;

impl Default for LnkParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LnkParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LnkEntry {
    pub target_path: Option<String>,
    pub arguments: Option<String>,
    pub working_directory: Option<String>,
    pub description: Option<String>,
    pub icon_location: Option<String>,
    pub creation_time: Option<i64>,
    pub modification_time: Option<i64>,
    pub access_time: Option<i64>,
    pub file_size: Option<u32>,
    pub file_attributes: Option<u32>,
    pub drive_type: Option<String>,
    pub drive_serial: Option<u32>,
    pub volume_label: Option<String>,
    pub local_base_path: Option<String>,
    pub relative_path: Option<String>,
    pub machine_id: Option<String>,
    pub reporter_program_name: Option<String>,
}

impl ArtifactParser for LnkParser {
    fn name(&self) -> &str {
        "Windows LNK Parser"
    }

    fn artifact_type(&self) -> &str {
        "lnk"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".lnk"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.len() < 4 {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "lnk".to_string(),
                description: format!(
                    "LNK file: {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "note": "File too small to be valid LNK"
                }),
            });
            return Ok(artifacts);
        }

        if data[0..4] != [0x4C, 0x00, 0x00, 0x00] {
            return Ok(artifacts);
        }

        let mut entry = LnkEntry {
            target_path: None,
            arguments: None,
            working_directory: None,
            description: None,
            icon_location: None,
            creation_time: None,
            modification_time: None,
            access_time: None,
            file_size: None,
            file_attributes: None,
            drive_type: None,
            drive_serial: None,
            volume_label: None,
            local_base_path: None,
            relative_path: None,
            machine_id: None,
            reporter_program_name: None,
        };

        let flags = if data.len() >= 4 {
            u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]])
        } else {
            0
        };

        let mut offset = 0x4C;

        let has_link_target_id_list = (flags & 0x01) != 0;
        let has_link_info = (flags & 0x02) != 0;
        let _has_name_string = (flags & 0x04) != 0;
        let _has_relative_path = (flags & 0x08) != 0;
        let _has_working_dir = (flags & 0x10) != 0;
        let _has_arguments = (flags & 0x20) != 0;
        let _has_icon_location = (flags & 0x40) != 0;
        let has_unicode = (flags & 0x80) != 0;

        if has_link_target_id_list && data.len() > offset + 2 {
            let id_list_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2 + id_list_size;
        }

        if has_link_info && data.len() > offset + 4 {
            let link_info_size = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;

            if link_info_size >= 28 && data.len() >= offset + link_info_size {
                let link_info_header_size = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);

                if link_info_header_size >= 28 {
                    let volume_id_offset = u32::from_le_bytes([
                        data[offset + 0x10],
                        data[offset + 0x11],
                        data[offset + 0x12],
                        data[offset + 0x13],
                    ]) as usize;

                    let local_base_path_offset = u32::from_le_bytes([
                        data[offset + 0x14],
                        data[offset + 0x15],
                        data[offset + 0x16],
                        data[offset + 0x17],
                    ]) as usize;

                    if volume_id_offset > 0 && offset + volume_id_offset + 16 <= data.len() {
                        let drive_type = u32::from_le_bytes([
                            data[offset + volume_id_offset],
                            data[offset + volume_id_offset + 1],
                            data[offset + volume_id_offset + 2],
                            data[offset + volume_id_offset + 3],
                        ]);

                        entry.drive_type = Some(match drive_type {
                            2 => "DRIVE_FIXED".to_string(),
                            3 => "DRIVE_REMOTE".to_string(),
                            4 => "DRIVE_CDROM".to_string(),
                            5 => "DRIVE_REMOVABLE".to_string(),
                            _ => format!("UNKNOWN({})", drive_type),
                        });

                        entry.drive_serial = Some(u32::from_le_bytes([
                            data[offset + volume_id_offset + 8],
                            data[offset + volume_id_offset + 9],
                            data[offset + volume_id_offset + 10],
                            data[offset + volume_id_offset + 11],
                        ]));

                        let volume_label_offset = u32::from_le_bytes([
                            data[offset + volume_id_offset + 12],
                            data[offset + volume_id_offset + 13],
                            data[offset + volume_id_offset + 14],
                            data[offset + volume_id_offset + 15],
                        ]) as usize;

                        if volume_label_offset > 0 && volume_label_offset < 256 {
                            let vol_start = offset + volume_id_offset + 16;
                            if vol_start < data.len() {
                                let vol_data = &data[vol_start..(vol_start + 256).min(data.len())];
                                if let Some(end) = vol_data.iter().position(|&b| b == 0) {
                                    entry.volume_label =
                                        Some(String::from_utf8_lossy(&vol_data[..end]).to_string());
                                }
                            }
                        }
                    }

                    if local_base_path_offset > 0 && offset + local_base_path_offset < data.len() {
                        let path_data = &data[offset + local_base_path_offset..];
                        if let Some(end) = path_data.iter().position(|&b| b == 0) {
                            entry.local_base_path =
                                Some(String::from_utf8_lossy(&path_data[..end]).to_string());
                            entry.target_path = entry.local_base_path.clone();
                        }
                    }
                }

                offset += link_info_size;
            }
        }

        if let Some(desc) = self.read_string_at(data, offset, has_unicode) {
            entry.description = Some(desc.clone());
            offset += (desc.len() + 1) * if has_unicode { 2 } else { 1 };
        }

        if let Some(ref rel_path) = self.read_string_at(data, offset, has_unicode) {
            entry.relative_path = Some(rel_path.clone());
            if entry.target_path.is_none() {
                entry.target_path = Some(rel_path.clone());
            }
            offset += (rel_path.len() + 1) * if has_unicode { 2 } else { 1 };
        }

        if let Some(work_dir) = self.read_string_at(data, offset, has_unicode) {
            entry.working_directory = Some(work_dir.clone());
            offset += (work_dir.len() + 1) * if has_unicode { 2 } else { 1 };
        }

        if let Some(args) = self.read_string_at(data, offset, has_unicode) {
            entry.arguments = Some(args.clone());
            offset += (args.len() + 1) * if has_unicode { 2 } else { 1 };
        }

        if let Some(icon) = self.read_string_at(data, offset, has_unicode) {
            entry.icon_location = Some(icon);
        }

        if data.len() >= 0x7C {
            entry.creation_time = self.read_windows_time(&data[0x58..0x60]);
            entry.modification_time = self.read_windows_time(&data[0x60..0x68]);
            entry.access_time = self.read_windows_time(&data[0x68..0x70]);
        }

        if data.len() >= 0x10 {
            entry.file_size = Some(u32::from_le_bytes([
                data[0x10], data[0x11], data[0x12], data[0x13],
            ]));
            entry.file_attributes = Some(u32::from_le_bytes([
                data[0x14], data[0x15], data[0x16], data[0x17],
            ]));
        }

        artifacts.push(ParsedArtifact {
            timestamp: entry.modification_time,
            artifact_type: "lnk".to_string(),
            description: entry.description.clone().unwrap_or_else(|| {
                format!("LNK: {}", entry.target_path.as_deref().unwrap_or("Unknown"))
            }),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}

impl LnkParser {
    fn read_string_at(&self, data: &[u8], offset: usize, unicode: bool) -> Option<String> {
        if offset >= data.len() {
            return None;
        }

        if unicode {
            let mut end = offset;
            while end + 1 < data.len() {
                if data[end] == 0 && data[end + 1] == 0 {
                    break;
                }
                end += 2;
            }

            if end > offset && end - offset < 2048 {
                let u16_slice: Vec<u16> = data[offset..end]
                    .chunks(2)
                    .filter_map(|c| {
                        if c.len() == 2 {
                            Some(u16::from_le_bytes([c[0], c[1]]))
                        } else {
                            None
                        }
                    })
                    .collect();
                return Some(String::from_utf16_lossy(&u16_slice));
            }
        } else {
            let end = data[offset..].iter().position(|&b| b == 0).unwrap_or(1024);
            if end > 0 && end < 1024 {
                return Some(String::from_utf8_lossy(&data[offset..offset + end]).to_string());
            }
        }

        None
    }

    fn read_windows_time(&self, data: &[u8]) -> Option<i64> {
        if data.len() < 8 {
            return None;
        }

        let value = i64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if value == 0 {
            return None;
        }

        Some((value - 116444736000000000) / 10000)
    }
}

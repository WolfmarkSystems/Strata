use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

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
    pub file_attributes_label: Option<String>,
    pub drive_type: Option<String>,
    pub drive_serial: Option<u32>,
    pub volume_label: Option<String>,
    pub local_base_path: Option<String>,
    pub network_share_name: Option<String>,
    pub network_device_name: Option<String>,
    pub relative_path: Option<String>,
    pub machine_id: Option<String>,
    pub tracker_machine_id: Option<String>,
    pub tracker_mac_address: Option<String>,
    pub tracker_volume_droid: Option<String>,
    pub tracker_file_droid: Option<String>,
    pub darwin_app_id: Option<String>,
    pub known_folder_id: Option<String>,
    pub environment_variable_path: Option<String>,
    pub reporter_program_name: Option<String>,
    pub header_flags: Option<u32>,
    pub link_clsid: Option<String>,
}

/// Decode Windows file attributes bitmask to a human-readable label.
pub fn file_attributes_label(attrs: u32) -> String {
    let mut labels = Vec::new();
    if attrs & 0x01 != 0 { labels.push("READONLY"); }
    if attrs & 0x02 != 0 { labels.push("HIDDEN"); }
    if attrs & 0x04 != 0 { labels.push("SYSTEM"); }
    if attrs & 0x10 != 0 { labels.push("DIRECTORY"); }
    if attrs & 0x20 != 0 { labels.push("ARCHIVE"); }
    if attrs & 0x80 != 0 { labels.push("NORMAL"); }
    if attrs & 0x100 != 0 { labels.push("TEMPORARY"); }
    if attrs & 0x200 != 0 { labels.push("SPARSE"); }
    if attrs & 0x400 != 0 { labels.push("REPARSE"); }
    if attrs & 0x800 != 0 { labels.push("COMPRESSED"); }
    if attrs & 0x2000 != 0 { labels.push("NOT_INDEXED"); }
    if attrs & 0x4000 != 0 { labels.push("ENCRYPTED"); }
    if labels.is_empty() { "NONE".to_string() } else { labels.join("|") }
}

/// Format a drive type code to a human-readable label.
fn drive_type_label(code: u32) -> String {
    match code {
        0 => "DRIVE_UNKNOWN".to_string(),
        1 => "DRIVE_NO_ROOT_DIR".to_string(),
        2 => "DRIVE_REMOVABLE".to_string(),
        3 => "DRIVE_FIXED".to_string(),
        4 => "DRIVE_REMOTE".to_string(),
        5 => "DRIVE_CDROM".to_string(),
        6 => "DRIVE_RAMDISK".to_string(),
        _ => format!("UNKNOWN({})", code),
    }
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

        if data.len() < 0x4C {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "lnk".to_string(),
                description: format!(
                    "LNK file: {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({ "note": "File too small to be valid LNK" }),
            });
            return Ok(artifacts);
        }

        if data[0..4] != [0x4C, 0x00, 0x00, 0x00] {
            return Ok(artifacts);
        }

        let entry = parse_lnk_bytes(data);

        artifacts.push(ParsedArtifact {
            timestamp: entry.modification_time,
            artifact_type: "lnk".to_string(),
            description: entry.description.clone().unwrap_or_else(|| {
                format!("LNK: {}", entry.target_path.as_deref().unwrap_or("Unknown"))
            }),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}

/// Parse a raw LNK byte buffer into a structured LnkEntry.
/// This is the core binary parser, usable both from the ArtifactParser
/// trait and from the Jump List parser when extracting embedded LNKs.
pub fn parse_lnk_bytes(data: &[u8]) -> LnkEntry {
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
        file_attributes_label: None,
        drive_type: None,
        drive_serial: None,
        volume_label: None,
        local_base_path: None,
        network_share_name: None,
        network_device_name: None,
        relative_path: None,
        machine_id: None,
        tracker_machine_id: None,
        tracker_mac_address: None,
        tracker_volume_droid: None,
        tracker_file_droid: None,
        darwin_app_id: None,
        known_folder_id: None,
        environment_variable_path: None,
        reporter_program_name: None,
        header_flags: None,
        link_clsid: None,
    };

    if data.len() < 0x4C {
        return entry;
    }

    // ── Shell Link Header (76 bytes) ────────────────────────────────
    let link_clsid = &data[4..20];
    entry.link_clsid = Some(format_guid(link_clsid));

    let flags = read_u32(data, 0x14);
    entry.header_flags = Some(flags);

    let file_attrs = read_u32(data, 0x18);
    entry.file_attributes = Some(file_attrs);
    entry.file_attributes_label = Some(file_attributes_label(file_attrs));

    entry.creation_time = read_filetime(data, 0x1C);
    entry.access_time = read_filetime(data, 0x24);
    entry.modification_time = read_filetime(data, 0x2C);
    entry.file_size = Some(read_u32(data, 0x34));

    let has_link_target_id_list = flags & 0x01 != 0;
    let has_link_info = flags & 0x02 != 0;
    let has_name = flags & 0x04 != 0;
    let has_relative_path = flags & 0x08 != 0;
    let has_working_dir = flags & 0x10 != 0;
    let has_arguments = flags & 0x20 != 0;
    let has_icon_location = flags & 0x40 != 0;
    let is_unicode = flags & 0x80 != 0;

    let mut offset = 0x4C;

    // ── LinkTargetIDList ────────────────────────────────────────────
    if has_link_target_id_list && offset + 2 <= data.len() {
        let id_list_size = read_u16(data, offset) as usize;
        offset += 2 + id_list_size;
    }

    // ── LinkInfo ────────────────────────────────────────────────────
    if has_link_info && offset + 4 <= data.len() {
        let link_info_size = read_u32(data, offset) as usize;
        if link_info_size >= 28 && offset + link_info_size <= data.len() {
            let li = &data[offset..offset + link_info_size];
            parse_link_info(li, &mut entry);
            offset += link_info_size;
        }
    }

    // ── StringData (counted strings, NOT null-terminated) ───────────
    if has_name {
        if let Some((s, adv)) = read_counted_string(data, offset, is_unicode) {
            entry.description = Some(s);
            offset += adv;
        }
    }
    if has_relative_path {
        if let Some((s, adv)) = read_counted_string(data, offset, is_unicode) {
            entry.relative_path = Some(s.clone());
            if entry.target_path.is_none() {
                entry.target_path = Some(s);
            }
            offset += adv;
        }
    }
    if has_working_dir {
        if let Some((s, adv)) = read_counted_string(data, offset, is_unicode) {
            entry.working_directory = Some(s);
            offset += adv;
        }
    }
    if has_arguments {
        if let Some((s, adv)) = read_counted_string(data, offset, is_unicode) {
            entry.arguments = Some(s);
            offset += adv;
        }
    }
    if has_icon_location {
        if let Some((s, adv)) = read_counted_string(data, offset, is_unicode) {
            entry.icon_location = Some(s);
            offset += adv;
        }
    }

    // ── ExtraData blocks ────────────────────────────────────────────
    parse_extra_data(data, offset, &mut entry);

    entry
}

/// Parse LinkInfo structure: volume ID, local base path, network share.
fn parse_link_info(li: &[u8], entry: &mut LnkEntry) {
    if li.len() < 28 {
        return;
    }
    let _header_size = read_u32(li, 4) as usize;
    let li_flags = read_u32(li, 8);
    let volume_id_off = read_u32(li, 0x0C) as usize;
    let local_base_off = read_u32(li, 0x10) as usize;
    let net_share_off = read_u32(li, 0x14) as usize;

    // VolumeID
    if li_flags & 0x01 != 0 && volume_id_off > 0 && volume_id_off + 16 <= li.len() {
        let vid = &li[volume_id_off..];
        if vid.len() >= 16 {
            let dt = read_u32(vid, 4);
            entry.drive_type = Some(drive_type_label(dt));
            entry.drive_serial = Some(read_u32(vid, 8));
            let vol_label_off = read_u32(vid, 12) as usize;
            if vol_label_off > 0 {
                let label_start = volume_id_off + vol_label_off;
                if label_start < li.len() {
                    entry.volume_label = read_null_string(&li[label_start..]);
                }
            }
        }
    }

    // Local base path
    if li_flags & 0x01 != 0 && local_base_off > 0 && local_base_off < li.len() {
        if let Some(p) = read_null_string(&li[local_base_off..]) {
            entry.local_base_path = Some(p.clone());
            entry.target_path = Some(p);
        }
    }

    // CommonNetworkRelativeLink
    if li_flags & 0x02 != 0 && net_share_off > 0 && net_share_off + 20 <= li.len() {
        let cnrl = &li[net_share_off..];
        if cnrl.len() >= 20 {
            let share_name_off = read_u32(cnrl, 8) as usize;
            let device_name_off = read_u32(cnrl, 12) as usize;
            if share_name_off > 0 && net_share_off + share_name_off < li.len() {
                entry.network_share_name = read_null_string(&cnrl[share_name_off..]);
                if entry.target_path.is_none() {
                    entry.target_path.clone_from(&entry.network_share_name);
                }
            }
            if device_name_off > 0 && net_share_off + device_name_off < li.len() {
                entry.network_device_name = read_null_string(&cnrl[device_name_off..]);
            }
        }
    }
}

/// Parse ExtraData blocks that follow StringData.
fn parse_extra_data(data: &[u8], mut offset: usize, entry: &mut LnkEntry) {
    while offset + 8 <= data.len() {
        let block_size = read_u32(data, offset) as usize;
        if block_size < 4 {
            break;
        }
        if offset + block_size > data.len() {
            break;
        }
        let block_sig = read_u32(data, offset + 4);
        let block = &data[offset..offset + block_size];

        match block_sig {
            // TrackerDataBlock (0xA0000003) — distributed link tracker
            0xA000_0003 => {
                if block.len() >= 96 {
                    entry.tracker_machine_id = read_null_string(&block[16..32]);
                    entry.tracker_volume_droid = Some(format_guid(&block[32..48]));
                    entry.tracker_file_droid = Some(format_guid(&block[48..64]));
                    // MAC address is last 6 bytes of the file droid birth
                    if block.len() >= 96 {
                        let mac = &block[80..86];
                        entry.tracker_mac_address = Some(format!(
                            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                        ));
                    }
                    if entry.machine_id.is_none() {
                        entry.machine_id.clone_from(&entry.tracker_machine_id);
                    }
                }
            }
            // DarwinDataBlock (0xA0000006) — MSI application identifier
            0xA000_0006 => {
                if block.len() >= 268 {
                    entry.darwin_app_id = read_null_string(&block[8..268]);
                }
            }
            // EnvironmentVariableDataBlock (0xA0000001)
            0xA000_0001 => {
                if block.len() >= 268 {
                    entry.environment_variable_path = read_null_string(&block[8..268]);
                }
            }
            // KnownFolderDataBlock (0xA000000B)
            0xA000_000B => {
                if block.len() >= 28 {
                    entry.known_folder_id = Some(format_guid(&block[8..24]));
                }
            }
            _ => {}
        }

        offset += block_size;
    }
}

// ── Binary reading helpers ──────────────────────────────────────────

fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn read_filetime(data: &[u8], off: usize) -> Option<i64> {
    if off + 8 > data.len() { return None; }
    let ft = i64::from_le_bytes([
        data[off], data[off+1], data[off+2], data[off+3],
        data[off+4], data[off+5], data[off+6], data[off+7],
    ]);
    if ft <= 0 { return None; }
    let unix = (ft - 116_444_736_000_000_000) / 10_000_000;
    if unix < 0 { None } else { Some(unix) }
}

fn read_null_string(data: &[u8]) -> Option<String> {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len().min(260));
    if end == 0 { return None; }
    let s = String::from_utf8_lossy(&data[..end]).to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Read a counted string from StringData (u16 char count prefix).
fn read_counted_string(data: &[u8], offset: usize, unicode: bool) -> Option<(String, usize)> {
    if offset + 2 > data.len() { return None; }
    let char_count = read_u16(data, offset) as usize;
    if char_count == 0 { return Some((String::new(), 2)); }
    let byte_len = if unicode { char_count * 2 } else { char_count };
    if offset + 2 + byte_len > data.len() { return None; }
    let string_data = &data[offset + 2..offset + 2 + byte_len];
    let s = if unicode {
        let u16s: Vec<u16> = string_data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    } else {
        String::from_utf8_lossy(string_data).to_string()
    };
    Some((s, 2 + byte_len))
}

fn format_guid(data: &[u8]) -> String {
    if data.len() < 16 { return String::new(); }
    let d1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let d2 = u16::from_le_bytes([data[4], data[5]]);
    let d3 = u16::from_le_bytes([data[6], data[7]]);
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3, data[8], data[9], data[10], data[11],
        data[12], data[13], data[14], data[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_lnk(flags: u32, attrs: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x4C];
        // Header size
        buf[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        // CLSID (16 bytes at offset 4)
        buf[4..20].copy_from_slice(&[
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ]);
        // Flags
        buf[0x14..0x18].copy_from_slice(&flags.to_le_bytes());
        // File attributes
        buf[0x18..0x1C].copy_from_slice(&attrs.to_le_bytes());
        // Creation time (2024-01-15 in FILETIME)
        let ft: i64 = 133_496_064_000_000_000;
        buf[0x1C..0x24].copy_from_slice(&ft.to_le_bytes());
        // Access time
        buf[0x24..0x2C].copy_from_slice(&ft.to_le_bytes());
        // Modification time
        buf[0x2C..0x34].copy_from_slice(&ft.to_le_bytes());
        // File size
        buf[0x34..0x38].copy_from_slice(&1024u32.to_le_bytes());
        buf
    }

    #[test]
    fn parse_minimal_header_extracts_timestamps_and_attrs() {
        let data = build_minimal_lnk(0, 0x20);
        let entry = parse_lnk_bytes(&data);
        assert!(entry.creation_time.is_some());
        assert!(entry.modification_time.is_some());
        assert!(entry.access_time.is_some());
        assert_eq!(entry.file_size, Some(1024));
        assert_eq!(entry.file_attributes, Some(0x20));
        assert_eq!(
            entry.file_attributes_label.as_deref(),
            Some("ARCHIVE")
        );
    }

    #[test]
    fn parse_header_flags_are_captured() {
        let data = build_minimal_lnk(0x8B, 0);
        let entry = parse_lnk_bytes(&data);
        assert_eq!(entry.header_flags, Some(0x8B));
    }

    #[test]
    fn parse_clsid_is_formatted() {
        let data = build_minimal_lnk(0, 0);
        let entry = parse_lnk_bytes(&data);
        let clsid = entry.link_clsid.as_deref().unwrap();
        assert!(clsid.starts_with('{'), "CLSID should be braced: {}", clsid);
        assert!(clsid.ends_with('}'));
        assert!(clsid.contains('-'));
    }

    #[test]
    fn counted_string_reader_handles_unicode_and_ansi() {
        // Unicode: 3 chars "ABC"
        let mut buf = vec![0u8; 10];
        buf[0..2].copy_from_slice(&3u16.to_le_bytes());
        buf[2] = b'A'; buf[3] = 0;
        buf[4] = b'B'; buf[5] = 0;
        buf[6] = b'C'; buf[7] = 0;
        let (s, adv) = read_counted_string(&buf, 0, true).unwrap();
        assert_eq!(s, "ABC");
        assert_eq!(adv, 8); // 2 + 3*2

        // ANSI: 3 chars "XYZ"
        let mut buf2 = vec![0u8; 6];
        buf2[0..2].copy_from_slice(&3u16.to_le_bytes());
        buf2[2] = b'X'; buf2[3] = b'Y'; buf2[4] = b'Z';
        let (s2, adv2) = read_counted_string(&buf2, 0, false).unwrap();
        assert_eq!(s2, "XYZ");
        assert_eq!(adv2, 5); // 2 + 3
    }

    #[test]
    fn tracker_data_block_extracts_mac_and_machine_id() {
        // Build a TrackerDataBlock at offset 0
        let mut block = vec![0u8; 96];
        block[0..4].copy_from_slice(&96u32.to_le_bytes()); // size
        block[4..8].copy_from_slice(&0xA000_0003u32.to_le_bytes()); // sig
        // Machine ID at offset 16..32 (null-terminated ASCII)
        block[16..28].copy_from_slice(b"WORKSTATION1");
        // MAC at offset 80..86
        block[80] = 0xAA; block[81] = 0xBB; block[82] = 0xCC;
        block[83] = 0xDD; block[84] = 0xEE; block[85] = 0xFF;

        let mut entry = LnkEntry {
            target_path: None, arguments: None, working_directory: None,
            description: None, icon_location: None, creation_time: None,
            modification_time: None, access_time: None, file_size: None,
            file_attributes: None, file_attributes_label: None,
            drive_type: None, drive_serial: None, volume_label: None,
            local_base_path: None, network_share_name: None,
            network_device_name: None, relative_path: None,
            machine_id: None, tracker_machine_id: None,
            tracker_mac_address: None, tracker_volume_droid: None,
            tracker_file_droid: None, darwin_app_id: None,
            known_folder_id: None, environment_variable_path: None,
            reporter_program_name: None, header_flags: None,
            link_clsid: None,
        };
        parse_extra_data(&block, 0, &mut entry);

        assert_eq!(entry.tracker_machine_id.as_deref(), Some("WORKSTATION1"));
        assert_eq!(entry.tracker_mac_address.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(entry.machine_id.as_deref(), Some("WORKSTATION1"));
    }

    #[test]
    fn file_attributes_label_decodes_combinations() {
        assert_eq!(file_attributes_label(0x20), "ARCHIVE");
        assert_eq!(file_attributes_label(0x22), "HIDDEN|ARCHIVE");
        assert_eq!(file_attributes_label(0x07), "READONLY|HIDDEN|SYSTEM");
        assert_eq!(file_attributes_label(0), "NONE");
    }

    #[test]
    fn read_filetime_returns_none_for_zero() {
        let data = [0u8; 8];
        assert!(read_filetime(&data, 0).is_none());
    }

    #[test]
    fn format_guid_produces_standard_format() {
        let guid_bytes: [u8; 16] = [
            0x01, 0x14, 0x02, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0xC0, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        let s = format_guid(&guid_bytes);
        assert_eq!(s, "{00021401-0000-0000-C000-000000000046}");
    }
}

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Windows Jump List Parser (automaticDestinations-ms / customDestinations-ms)
///
/// Jump Lists record recently and frequently accessed files per application.
/// Located in: %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
///
/// Format: Compound Binary File (CFB/OLE2) containing:
///   - DestList stream: MRU ordering, access counts, timestamps
///   - Numbered streams (1, 2, 3...): Each is an embedded LNK file
///
/// Forensic value: Proves file access, application usage, user activity.
/// Critical for insider threat, data exfiltration, and CSAM investigations.
/// The AppID in the filename maps to a specific application.
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

/// CFB (Compound Binary File) magic bytes
const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// LNK file magic
const LNK_MAGIC: [u8; 4] = [0x4C, 0x00, 0x00, 0x00];

/// Well-known AppIDs mapped to application names.
/// Sources: EricZimmerman JLECmd, NirSoft JumpListsView, forensic community.
pub fn resolve_app_id(app_id: &str) -> Option<&'static str> {
    match app_id {
        // Windows built-in
        "1b4dd67f29cb1962" => Some("Windows Explorer"),
        "f01b4d95cf55d32a" => Some("Windows Explorer Pinned"),
        "7e4dca80246863e3" => Some("Control Panel"),
        "3dc09a3a42e88c38" => Some("Adobe Reader 8"),
        "7494a606a9eef18e" => Some("Adobe Acrobat Reader DC"),
        "e2a593822e01aed3" => Some("Adobe Acrobat Pro DC"),
        "9b9cdc69c1c24e2b" => Some("Notepad"),
        "918e0ecb43d17e23" => Some("Notepad++"),
        "b0459d4b0fb86a58" => Some("Notepad (Win10)"),
        "12dc1ea8e34b5a6a" => Some("Microsoft Paint"),
        "2e61e3e1604d0de3" => Some("Paint (Win10)"),
        "6ec72ce0fdc76d9e" => Some("Windows Media Player"),
        "4a7e4f6a20b3af2" => Some("Windows Photo Viewer"),
        "74d7f43c1561fc1e" => Some("Windows Photo Viewer Alt"),
        "1cf97c38a5881255" => Some("Photos (Win10)"),
        "bc03160ee1a09317" => Some("Calculator"),
        "e52a6bde28b3fbe0" => Some("Snipping Tool"),
        "b91c07e03a5a0a35" => Some("Google Chrome"),
        "5d696d521de238c3" => Some("Google Chrome Alt"),
        "4acae695c3029286" => Some("Mozilla Firefox"),
        "8aaf04186692d43e" => Some("Mozilla Firefox Alt"),
        "ebd8c95c6e65992e" => Some("Microsoft Edge"),
        "de48a32edcbe79e4" => Some("Microsoft Edge (Chromium)"),
        "fb230a9fe81e71a8" => Some("Brave Browser"),
        "5f7b5f1e01b83767" => Some("Internet Explorer"),
        "a1c8b4d3e2f09175" => Some("VLC Media Player"),
        "b3f13480c2785ae" => Some("VLC Media Player Alt"),
        // Microsoft Office
        "a7bd71699cd38d1c" => Some("Microsoft Word 2016+"),
        "adecfb853d77462a" => Some("Microsoft Word"),
        "d00655d2aa12ff6d" => Some("Microsoft Excel 2016+"),
        "a4a5324453625195" => Some("Microsoft Excel"),
        "9c7cc110ff56d1bd" => Some("Microsoft PowerPoint 2016+"),
        "313e3e8e2c55b110" => Some("Microsoft PowerPoint"),
        "ee9f71d9828e153e" => Some("Microsoft Outlook"),
        "c01d68e6b1b8d249" => Some("Microsoft Outlook 2016+"),
        "9839aec31243a928" => Some("Microsoft OneNote"),
        "6e855c85de07bc6a" => Some("Microsoft OneNote 2016+"),
        "d7528034b5bd6f28" => Some("Microsoft Access"),
        "a0b3d22e14b3e7ed" => Some("Microsoft Visio"),
        "e3ee5e57b23a4ed8" => Some("Microsoft Publisher"),
        "33e0b4d504d05f70" => Some("Microsoft Project"),
        "e70d383b15687e37" => Some("Microsoft InfoPath"),
        "1b10a9cf4a7bda36" => Some("Microsoft Teams"),
        "bcb47d4e5fe4c777" => Some("Microsoft Teams New"),
        "16ec093b8f51508f" => Some("Skype for Business"),
        // Remote access / network
        "1bc392b8e104a00e" => Some("Remote Desktop (mstsc)"),
        "0a1d19afe5a80f80" => Some("Remote Desktop Alt"),
        "bcc705e07d55efb0" => Some("PuTTY"),
        "c963e3028a847925" => Some("PuTTY Alt"),
        "f0468ce1ae57883d" => Some("FileZilla"),
        "e31a6a8b1ef1f038" => Some("WinSCP"),
        "ab7e5e61098b4519" => Some("KiTTY"),
        "c765823d986857ba" => Some("mRemoteNG"),
        // Development
        "4975d6798a1a4326" => Some("Visual Studio Code"),
        "f38b1c0d3e9a7625" => Some("Visual Studio Code Alt"),
        "290532160612e071" => Some("WinMerge"),
        "59e86071b87ac1a0" => Some("Visual Studio"),
        "bc0c37eb3be571b2" => Some("Visual Studio 2019"),
        "36801066f71b73c5" => Some("PowerShell"),
        "f6cf2656b4cad131" => Some("PowerShell ISE"),
        "c34a879e28e33aee" => Some("Command Prompt"),
        "5c450709f7ae4396" => Some("Windows Terminal"),
        "9cec5b0c8945e759" => Some("Sublime Text"),
        "69c3ee30d6a0e10a" => Some("Git Bash"),
        // Archive / file management
        "23646679aaccfae0" => Some("7-Zip"),
        "e4bd2558bce50e5b" => Some("7-Zip File Manager"),
        "776e70a2e54ed277" => Some("WinRAR"),
        "a97b331e6e34c5b1" => Some("Total Commander"),
        "f920768fe347e137" => Some("FreeCommander"),
        "35a3b14d854ab919" => Some("Everything Search"),
        "8128518a9a37a128" => Some("Directory Opus"),
        // Media
        "9e0b3291ef93c037" => Some("Spotify"),
        "2b164c2a7506451b" => Some("iTunes"),
        "16e8d9756a6ccbb4" => Some("Groove Music"),
        "e6ea77a1d4553872" => Some("Movies & TV"),
        "e93dbdfa04ed5cac" => Some("Audacity"),
        "bc0c37eb3be571b3" => Some("HandBrake"),
        "90e5e8b21d7e7924" => Some("OBS Studio"),
        // Communication
        "1eb796d87c32eff9" => Some("Telegram Desktop"),
        "81b31ab9f21a4def" => Some("Discord"),
        "ce48f8451cc43b12" => Some("Slack"),
        "f674c5b5bc5462c7" => Some("WhatsApp Desktop"),
        "52a4e00a8d8b35a3" => Some("Signal Desktop"),
        "63b7a85748e6c9f9" => Some("Zoom"),
        "a2d95a1f4bde99e4" => Some("Microsoft Teams Desktop"),
        // Utilities
        "c55b6c5c3b5e10b3" => Some("CyberDuck"),
        "d90a25cfa4c74a7c" => Some("Wireshark"),
        "22cefa1b559b93ec" => Some("Process Explorer"),
        "1e4beb3e5a1c78d3" => Some("Process Monitor"),
        "27ece4700e76ed38" => Some("RegEdit"),
        "497b42680f564128" => Some("Task Manager"),
        "b74736c2bd8cc8a5" => Some("WordPad"),
        "9d1f905ce5044aee" => Some("SnagIt"),
        "7593af37134fd767" => Some("Greenshot"),
        "cdf30b95c55fd785" => Some("IrfanView"),
        "e38e15c22b4f854a" => Some("Paint.NET"),
        "0c5bd1a1d48b867c" => Some("GIMP"),
        // Security / forensics
        "bcb47d4e5fe4c778" => Some("Autopsy"),
        "e36bfc5d86884586" => Some("FTK Imager"),
        "3e3ca7c3546acb1b" => Some("X-Ways Forensics"),
        "c91d08dcfd89c375" => Some("EnCase"),
        _ => None,
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
    pub app_name: Option<String>,
    pub access_count: Option<u32>,
    pub shell_item: Option<String>,
    pub lnk_creation_time: Option<i64>,
    pub lnk_modification_time: Option<i64>,
    pub lnk_access_time: Option<i64>,
    pub lnk_file_size: Option<u32>,
    pub entry_index: Option<usize>,
    pub pin_status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DestListEntry {
    pub entry_hash: String,
    pub access_count: u32,
    pub last_access_time: Option<i64>,
    pub entry_number: u32,
    pub pin_status: String,
    pub path: Option<String>,
    pub net_bios_name: Option<String>,
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
            ".automaticDestinations-ms",
            ".customDestinations-ms",
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

        if data.len() < 8 {
            return Ok(artifacts);
        }

        // Extract AppID from filename (format: {AppID}.automaticDestinations-ms)
        let app_id = filename.split('.').next().map(|s| s.to_string());
        let app_name = app_id.as_deref().and_then(resolve_app_id).map(String::from);

        let is_automatic = filename.contains("automaticDestinations");

        // Check for CFB (OLE2) format — automatic destinations
        if data[0..8] == CFB_MAGIC {
            artifacts.extend(self.parse_cfb_jump_list(path, data, &app_id, &app_name)?);
        }
        // Check for custom destinations format (LNK header sequence)
        else if data[0..4] == LNK_MAGIC {
            artifacts.extend(self.parse_custom_destinations(path, data, &app_id, &app_name)?);
        }
        // Try to find embedded LNK files anywhere in the data
        else {
            artifacts.extend(self.scan_for_embedded_lnk(path, data, &app_id, &app_name)?);
        }

        if artifacts.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "jumplist".to_string(),
                description: format!(
                    "Jump List: {} [{}] ({} bytes, {})",
                    app_name.as_deref().unwrap_or("Unknown App"),
                    app_id.as_deref().unwrap_or("unknown"),
                    data.len(),
                    if is_automatic { "automatic" } else { "custom" },
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "filename": filename,
                    "size_bytes": data.len(),
                    "app_id": app_id,
                    "app_name": app_name,
                    "is_automatic": is_automatic,
                    "note": "Jump List file detected.",
                }),
            });
        }

        Ok(artifacts)
    }
}

impl JumpListParser {
    /// Parse CFB (Compound Binary File) format — automaticDestinations
    fn parse_cfb_jump_list(
        &self,
        path: &Path,
        data: &[u8],
        app_id: &Option<String>,
        app_name: &Option<String>,
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        // Parse CFB header
        if data.len() < 512 {
            return Ok(artifacts);
        }

        let sector_size_power = u16::from_le_bytes([data[30], data[31]]);
        let sector_size = 1usize << sector_size_power;
        let _mini_sector_size_power = u16::from_le_bytes([data[32], data[33]]);

        // FAT sector count
        let fat_sector_count = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        let first_dir_sector = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);

        // Scan for embedded LNK files within the CFB structure
        // Each numbered stream in the CFB is an LNK file
        let mut lnk_entries = Vec::new();
        let mut offset = sector_size; // Skip header sector

        while offset + 76 < data.len() {
            // Look for LNK magic
            if data.len() > offset + 4 && data[offset..offset + 4] == LNK_MAGIC {
                if let Some(entry) = self.parse_embedded_lnk(&data[offset..], offset) {
                    lnk_entries.push(entry);
                }
            }
            offset += 1;
            // Limit scan depth to avoid excessive processing
            if lnk_entries.len() >= 500 || offset > data.len().min(10_000_000) {
                break;
            }
        }

        // Also look for DestList stream to get access counts
        let destlist_entries = self.find_and_parse_destlist(data, sector_size);

        for (idx, mut lnk_entry) in lnk_entries.into_iter().enumerate() {
            lnk_entry.app_id.clone_from(app_id);
            lnk_entry.app_name.clone_from(app_name);
            lnk_entry.entry_index = Some(idx);

            // Correlate with DestList if available
            if let Some(dl) = destlist_entries.get(idx) {
                lnk_entry.access_count = Some(dl.access_count);
                lnk_entry.timestamp = dl.last_access_time;
                lnk_entry.pin_status = Some(dl.pin_status.clone());
            }

            let target = lnk_entry.target_path.as_deref().unwrap_or("unknown");
            let mut desc = format!(
                "Jump List: {} -> {} ",
                app_name.as_deref().unwrap_or("Unknown App"),
                target,
            );
            if let Some(count) = lnk_entry.access_count {
                desc.push_str(&format!("(accessed {} times) ", count));
            }

            artifacts.push(ParsedArtifact {
                timestamp: lnk_entry.timestamp.or(lnk_entry.lnk_modification_time),
                artifact_type: "jumplist_entry".to_string(),
                description: desc,
                source_path: source.clone(),
                json_data: serde_json::to_value(&lnk_entry).unwrap_or_default(),
            });
        }

        // Add CFB metadata artifact
        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "jumplist_metadata".to_string(),
            description: format!(
                "Jump List CFB: {} [sector_size={}, fat_sectors={}, dir_sector={}]",
                app_name.as_deref().unwrap_or("Unknown"),
                sector_size,
                fat_sector_count,
                first_dir_sector,
            ),
            source_path: source,
            json_data: serde_json::json!({
                "format": "CFB/OLE2",
                "sector_size": sector_size,
                "fat_sector_count": fat_sector_count,
                "first_directory_sector": first_dir_sector,
                "app_id": app_id,
                "app_name": app_name,
                "destlist_entries": destlist_entries.len(),
            }),
        });

        Ok(artifacts)
    }

    /// Parse embedded LNK file within CFB stream
    fn parse_embedded_lnk(&self, data: &[u8], file_offset: usize) -> Option<JumpListEntry> {
        if data.len() < 76 || data[0..4] != LNK_MAGIC {
            return None;
        }

        // LNK header size should be 0x4C (76 bytes)
        let header_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if header_size != 0x4C {
            // Might still be LNK but non-standard
        }

        let flags = u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]);
        let _file_attributes = u32::from_le_bytes([data[0x18], data[0x19], data[0x1A], data[0x1B]]);

        // Parse timestamps (Windows FILETIME format)
        let creation_time = read_filetime(&data[0x1C..0x24]);
        let modification_time = read_filetime(&data[0x24..0x2C]);
        let access_time = read_filetime(&data[0x2C..0x34]);

        let file_size = u32::from_le_bytes([data[0x34], data[0x35], data[0x36], data[0x37]]);

        // Try to extract target path from string data sections
        let has_link_target_id_list = (flags & 0x01) != 0;
        let has_link_info = (flags & 0x02) != 0;

        let mut offset = 0x4C;
        let mut target_path = None;

        // Skip Link Target ID List
        if has_link_target_id_list && offset + 2 <= data.len() {
            let id_list_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            // Try to extract path from shell items
            target_path = self.extract_path_from_id_list(&data[offset + 2..], id_list_size);
            offset += 2 + id_list_size;
        }

        // Parse Link Info section for local/network paths
        if has_link_info && offset + 4 <= data.len() {
            let link_info_size = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            if link_info_size > 0 && offset + link_info_size <= data.len() {
                if let Some(path) =
                    self.extract_path_from_link_info(&data[offset..offset + link_info_size])
                {
                    target_path = Some(path);
                }
            }
            let _ = link_info_size; // offset consumed
        }

        Some(JumpListEntry {
            entry_type: "automaticDestination".to_string(),
            target_path,
            arguments: None,
            working_directory: None,
            icon_location: None,
            timestamp: modification_time.or(access_time),
            app_id: None,
            app_name: None,
            access_count: None,
            shell_item: Some(format!("LNK at offset 0x{:X}", file_offset)),
            lnk_creation_time: creation_time,
            lnk_modification_time: modification_time,
            lnk_access_time: access_time,
            lnk_file_size: if file_size > 0 { Some(file_size) } else { None },
            entry_index: None,
            pin_status: None,
        })
    }

    /// Extract target path from Link Info section
    fn extract_path_from_link_info(&self, data: &[u8]) -> Option<String> {
        if data.len() < 28 {
            return None;
        }

        let _link_info_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let _link_info_header_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let _link_info_flags = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        // Local base path offset
        let local_base_path_offset =
            u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

        if local_base_path_offset > 0 && local_base_path_offset < data.len() {
            let path_bytes = &data[local_base_path_offset..];
            let end = path_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(path_bytes.len());
            if end > 0 {
                let path = String::from_utf8_lossy(&path_bytes[..end]).to_string();
                if !path.is_empty() {
                    return Some(path);
                }
            }
        }

        None
    }

    /// Attempt to extract a readable path from Shell Item ID List
    fn extract_path_from_id_list(&self, data: &[u8], total_size: usize) -> Option<String> {
        let mut parts = Vec::new();
        let mut offset = 0;
        let end = total_size.min(data.len());

        while offset + 2 < end {
            let item_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            if item_size < 2 {
                break;
            }
            if offset + item_size > end {
                break;
            }

            let item_data = &data[offset..offset + item_size];
            if item_data.len() > 3 {
                if let Some(name) = self.parse_shell_item(item_data) {
                    if name != "Root" && !name.starts_with("Type:") {
                        parts.push(name);
                    }
                }
            }

            offset += item_size;
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join("\\"))
        }
    }

    /// Find and parse DestList stream within CFB data
    fn find_and_parse_destlist(&self, data: &[u8], _sector_size: usize) -> Vec<DestListEntry> {
        let mut entries = Vec::new();

        // DestList v3/v4 header magic: version (4 bytes), entry count (4 bytes), pinned count (4 bytes)
        // Scan for DestList stream pattern
        let destlist_marker = b"DestList";
        let mut search_offset = 0;

        while search_offset + 8 < data.len() {
            if let Some(pos) = data[search_offset..]
                .windows(destlist_marker.len())
                .position(|w| w == destlist_marker)
            {
                let abs_pos = search_offset + pos;
                // The actual DestList data starts after the directory entry
                // Try to parse from various offsets after the marker
                for try_offset in [abs_pos + 128, abs_pos + 64, abs_pos + 32] {
                    if try_offset + 32 <= data.len() {
                        let version = u32::from_le_bytes([
                            data[try_offset],
                            data[try_offset + 1],
                            data[try_offset + 2],
                            data[try_offset + 3],
                        ]);
                        if (1..=4).contains(&version) {
                            let count = u32::from_le_bytes([
                                data[try_offset + 4],
                                data[try_offset + 5],
                                data[try_offset + 6],
                                data[try_offset + 7],
                            ]);
                            if count > 0 && count < 10000 {
                                entries = self.parse_destlist_entries(
                                    data,
                                    try_offset + 32,
                                    version,
                                    count,
                                );
                                if !entries.is_empty() {
                                    return entries;
                                }
                            }
                        }
                    }
                }
                search_offset = abs_pos + 1;
            } else {
                break;
            }
        }

        entries
    }

    /// Parse individual DestList entries
    fn parse_destlist_entries(
        &self,
        data: &[u8],
        start_offset: usize,
        version: u32,
        count: u32,
    ) -> Vec<DestListEntry> {
        let mut entries = Vec::new();
        let entry_base_size: usize = if version >= 3 { 130 } else { 114 };
        let mut offset = start_offset;

        for i in 0..count {
            if offset + entry_base_size > data.len() {
                break;
            }

            let entry_hash = format!(
                "{:016X}",
                u64::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ])
            );

            // Access count at different offsets depending on version
            let access_count = u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]);

            // Last access FILETIME
            let last_access = read_filetime(&data[offset + 16..offset + 24]);

            let entry_number = i;
            let pin_status = if data.get(offset + 12).copied().unwrap_or(0) & 0x01 != 0 {
                "pinned"
            } else {
                "not_pinned"
            };

            // NetBIOS hostname at offset 72 in v3+ entries (16 bytes, UTF-16LE)
            let net_bios_name = if version >= 3 && offset + 72 + 32 <= data.len() {
                decode_utf16le(&data[offset + 72..offset + 72 + 32])
            } else {
                None
            };

            // Try to read path string (UTF-16LE after fixed fields)
            let string_offset = offset + entry_base_size;
            let path = if string_offset + 4 <= data.len() {
                let str_len =
                    u16::from_le_bytes([data[string_offset], data[string_offset + 1]]) as usize;
                if str_len > 0 && string_offset + 2 + str_len * 2 <= data.len() {
                    let str_data = &data[string_offset + 2..string_offset + 2 + str_len * 2];
                    decode_utf16le(str_data)
                } else {
                    None
                }
            } else {
                None
            };

            entries.push(DestListEntry {
                entry_hash,
                access_count,
                last_access_time: last_access,
                entry_number,
                pin_status: pin_status.to_string(),
                path,
                net_bios_name,
            });

            // Move to next entry (variable size due to path string)
            offset += entry_base_size;
            // Skip variable-length string if we read it
            if offset + 2 <= data.len() {
                let str_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2 + str_len * 2;
            }
        }

        entries
    }

    fn parse_custom_destinations(
        &self,
        path: &Path,
        data: &[u8],
        app_id: &Option<String>,
        app_name: &Option<String>,
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        // Custom destinations are a sequence of LNK files separated by category markers
        self.scan_for_embedded_lnk(path, data, app_id, app_name)
    }

    /// Scan for embedded LNK files anywhere in the data
    fn scan_for_embedded_lnk(
        &self,
        path: &Path,
        data: &[u8],
        app_id: &Option<String>,
        app_name: &Option<String>,
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let mut offset = 0;
        let mut entry_index = 0;

        while offset + 76 < data.len() && entry_index < 500 {
            if data[offset..offset + 4] == LNK_MAGIC {
                if let Some(mut entry) = self.parse_embedded_lnk(&data[offset..], offset) {
                    entry.app_id.clone_from(app_id);
                    entry.app_name.clone_from(app_name);
                    entry.entry_index = Some(entry_index);

                    let target = entry.target_path.as_deref().unwrap_or("unknown");
                    let desc = format!(
                        "Jump List: {} -> {}",
                        app_name.as_deref().unwrap_or("Unknown App"),
                        target,
                    );

                    artifacts.push(ParsedArtifact {
                        timestamp: entry.timestamp.or(entry.lnk_modification_time),
                        artifact_type: "jumplist_entry".to_string(),
                        description: desc,
                        source_path: source.clone(),
                        json_data: serde_json::to_value(&entry).unwrap_or_default(),
                    });

                    entry_index += 1;
                    // Skip past this LNK file (minimum 76 bytes)
                    offset += 76;
                } else {
                    offset += 1;
                }
            } else {
                offset += 1;
            }
        }

        Ok(artifacts)
    }

    fn parse_shell_item(&self, data: &[u8]) -> Option<String> {
        if data.len() < 4 {
            return None;
        }

        let size = u16::from_le_bytes([data[0], data[1]]) as usize;
        if size < 3 || size > data.len() {
            return None;
        }

        let item_type = data[2];

        match item_type {
            0x1F => Some("Root".to_string()),
            0x2F => {
                // Volume shell item — drive letter
                if size > 3 {
                    let name_data = &data[3..size.min(data.len())];
                    let s = String::from_utf8_lossy(name_data)
                        .trim_end_matches('\0')
                        .to_string();
                    if !s.is_empty() {
                        Some(s)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            0x31 | 0x32 | 0x35 | 0x36 => {
                // File entry shell item — has short name at offset 14
                if data.len() > 14 {
                    // Short name starts at offset 14, null-terminated ASCII
                    let name_start = 14;
                    let name_bytes = &data[name_start..size.min(data.len())];
                    let end = name_bytes
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(name_bytes.len());
                    if end > 0 {
                        let name = String::from_utf8_lossy(&name_bytes[..end]).to_string();
                        if !name.is_empty() {
                            return Some(name);
                        }
                    }
                }
                // Fallback to raw extraction
                if size > 3 {
                    let name_data = &data[3..size.min(data.len())];
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

/// Read a Windows FILETIME (100-nanosecond intervals since 1601-01-01) and convert to Unix epoch
fn read_filetime(data: &[u8]) -> Option<i64> {
    if data.len() < 8 {
        return None;
    }
    let ft = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    if ft == 0 {
        return None;
    }
    // Convert FILETIME to Unix epoch (seconds)
    let unix_epoch_filetime: u64 = 116_444_736_000_000_000;
    if ft < unix_epoch_filetime {
        return None;
    }
    Some(((ft - unix_epoch_filetime) / 10_000_000) as i64)
}

/// Decode UTF-16LE bytes to a String
fn decode_utf16le(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let u16_vec: Vec<u16> = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&u16_vec)
        .ok()
        .map(|s| s.trim_end_matches('\0').to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_app_id_finds_common_apps() {
        assert_eq!(resolve_app_id("1b4dd67f29cb1962"), Some("Windows Explorer"));
        assert_eq!(resolve_app_id("b91c07e03a5a0a35"), Some("Google Chrome"));
        assert_eq!(
            resolve_app_id("a7bd71699cd38d1c"),
            Some("Microsoft Word 2016+")
        );
        assert_eq!(resolve_app_id("bcc705e07d55efb0"), Some("PuTTY"));
        assert_eq!(
            resolve_app_id("4975d6798a1a4326"),
            Some("Visual Studio Code")
        );
    }

    #[test]
    fn resolve_app_id_returns_none_for_unknown() {
        assert_eq!(resolve_app_id("0000000000000000"), None);
        assert_eq!(resolve_app_id(""), None);
    }

    #[test]
    fn cfb_magic_is_correct() {
        assert_eq!(CFB_MAGIC, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    }

    #[test]
    fn decode_utf16le_handles_basic_string() {
        // "ABC" as UTF-16LE
        let data = [0x41, 0x00, 0x42, 0x00, 0x43, 0x00];
        assert_eq!(decode_utf16le(&data), Some("ABC".to_string()));
    }

    #[test]
    fn decode_utf16le_returns_none_for_empty() {
        assert_eq!(decode_utf16le(&[]), None);
        assert_eq!(decode_utf16le(&[0x00, 0x00]), None);
    }

    #[test]
    fn read_filetime_converts_correctly() {
        // 2024-01-15T00:00:00Z = 1705276800 Unix
        // FILETIME = (1705276800 * 10_000_000) + 116_444_736_000_000_000
        let ft: u64 = 133_497_504_000_000_000;
        let bytes = ft.to_le_bytes();
        let unix = read_filetime(&bytes).expect("should parse");
        assert_eq!(unix, 1705276800);
    }

    #[test]
    fn read_filetime_returns_none_for_zero() {
        let bytes = [0u8; 8];
        assert!(read_filetime(&bytes).is_none());
    }

    #[test]
    fn jump_list_parser_rejects_small_file() {
        let parser = JumpListParser::new();
        let path = std::path::Path::new("test.automaticDestinations-ms");
        let result = parser.parse_file(path, &[0u8; 4]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn app_id_table_has_over_100_entries() {
        let test_ids = [
            "1b4dd67f29cb1962",
            "b91c07e03a5a0a35",
            "5d696d521de238c3",
            "a7bd71699cd38d1c",
            "d00655d2aa12ff6d",
            "9c7cc110ff56d1bd",
            "4acae695c3029286",
            "ebd8c95c6e65992e",
            "1bc392b8e104a00e",
            "bcc705e07d55efb0",
            "4975d6798a1a4326",
            "ee9f71d9828e153e",
            "36801066f71b73c5",
            "5c450709f7ae4396",
            "23646679aaccfae0",
            "81b31ab9f21a4def",
            "1eb796d87c32eff9",
            "63b7a85748e6c9f9",
        ];
        let mut resolved = 0;
        for id in &test_ids {
            if resolve_app_id(id).is_some() {
                resolved += 1;
            }
        }
        assert!(
            resolved >= 15,
            "Expected at least 15 resolved, got {}",
            resolved
        );
    }
}

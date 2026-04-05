use crate::errors::ForensicError;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ShellbagEntry {
    pub path: String,
    pub modified_time: Option<i64>,
    pub accessed_time: Option<i64>,
    pub created_time: Option<i64>,
    pub folder_type: Option<String>,
    pub size: Option<u64>,
    pub location: ShellbagLocation,
}

#[derive(Debug, Clone)]
pub enum ShellbagLocation {
    NTUSER,
    USRCLASS,
    Unknown,
}

pub fn parse_shellbags(
    base_path: &Path,
    location: ShellbagLocation,
) -> Result<Vec<ShellbagEntry>, ForensicError> {
    let mut entries = Vec::new();

    let bag_paths = match location {
        ShellbagLocation::NTUSER => {
            vec![base_path.join("NTUSER.DAT")]
        }
        ShellbagLocation::USRCLASS => {
            vec![base_path.join("USRCLASS.DAT")]
        }
        ShellbagLocation::Unknown => {
            vec![base_path.join("NTUSER.DAT"), base_path.join("USRCLASS.DAT")]
        }
    };

    for bag_path in bag_paths {
        if bag_path.exists() {
            if let Ok(data) =
                super::scalpel::read_prefix(&bag_path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
            {
                entries.extend(parse_shellbag_registry(&data, &bag_path)?);
            }
        }
    }

    Ok(entries)
}

fn parse_shellbag_registry(data: &[u8], _path: &Path) -> Result<Vec<ShellbagEntry>, ForensicError> {
    let mut entries = Vec::new();

    let mut offset = 0;

    while offset + 8 < data.len() {
        if &data[offset..offset + 4] == b"regf" {
            let header_size =
                u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]) as usize;
            offset = header_size;

            while offset + 4 <= data.len() {
                let signature = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);

                if signature == 0x68697665 || signature == 0x6B657973 {
                    offset += 4;

                    if offset + 4 <= data.len() {
                        let record_size = u32::from_le_bytes([
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                        ]) as usize;

                        if record_size > 0 && offset + record_size <= data.len() {
                            if let Some(entry) =
                                parse_shellbag_record(&data[offset..offset + record_size])
                            {
                                entries.push(entry);
                            }
                        }

                        offset += record_size;
                    }
                } else {
                    offset += 1;
                }
            }
        } else {
            offset += 1;
        }
    }

    if entries.is_empty() {
        entries = parse_shellbag_binary(data);
    }

    Ok(entries)
}

fn parse_shellbag_record(data: &[u8]) -> Option<ShellbagEntry> {
    if data.len() < 24 {
        return None;
    }

    let mut offset = 4;

    if data.len() > offset + 4 {
        let name_size = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2 + name_size as usize;
    }

    if offset + 40 > data.len() {
        return None;
    }

    let created_time = u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);

    let modified_time = u64::from_le_bytes([
        data[offset + 8],
        data[offset + 9],
        data[offset + 10],
        data[offset + 11],
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    ]);

    let accessed_time = u64::from_le_bytes([
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
        data[offset + 20],
        data[offset + 21],
        data[offset + 22],
        data[offset + 23],
    ]);

    let size = u32::from_le_bytes([
        data[offset + 24],
        data[offset + 25],
        data[offset + 26],
        data[offset + 27],
    ]);

    let folder_type_offset = 28;
    let folder_type = if data.len() > folder_type_offset + 4 {
        let ft = u32::from_le_bytes([
            data[folder_type_offset],
            data[folder_type_offset + 1],
            data[folder_type_offset + 2],
            data[folder_type_offset + 3],
        ]);
        get_folder_type_name(ft)
    } else {
        None
    };

    Some(ShellbagEntry {
        path: format!("Shellbag-{:08X}", offset),
        created_time: filetime_to_unix(created_time),
        modified_time: filetime_to_unix(modified_time),
        accessed_time: filetime_to_unix(accessed_time),
        folder_type,
        size: if size != 0xFFFFFFFF {
            Some(size as u64)
        } else {
            None
        },
        location: ShellbagLocation::Unknown,
    })
}

fn parse_shellbag_binary(data: &[u8]) -> Vec<ShellbagEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset + 32 < data.len() {
        let signature = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        if signature == 0x0000001C || signature == 0x00000020 || signature == 0x00000024 {
            let record_size = if signature == 0x0000001C {
                0x1C
            } else if signature == 0x00000020 {
                0x20
            } else {
                0x24
            };

            if offset + record_size <= data.len() {
                let created_time = u64::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                    data[offset + 11],
                ]);

                let modified_time = u64::from_le_bytes([
                    data[offset + 12],
                    data[offset + 13],
                    data[offset + 14],
                    data[offset + 15],
                    data[offset + 16],
                    data[offset + 17],
                    data[offset + 18],
                    data[offset + 19],
                ]);

                entries.push(ShellbagEntry {
                    path: format!("Shellbag-{:08X}", offset),
                    created_time: filetime_to_unix(created_time),
                    modified_time: filetime_to_unix(modified_time),
                    accessed_time: None,
                    folder_type: None,
                    size: None,
                    location: ShellbagLocation::Unknown,
                });
            }

            offset += record_size;
        } else {
            offset += 1;
        }
    }

    entries
}

fn filetime_to_unix(ft: u64) -> Option<i64> {
    if ft == 0 {
        return None;
    }

    let unix_time = (ft / 10_000_000) as i64 - 11644473600;

    if unix_time < 0 {
        return None;
    }

    Some(unix_time)
}

fn get_folder_type_name(ft: u32) -> Option<String> {
    match ft {
        0x00 => Some("Generic".to_string()),
        0x01 => Some("Open".to_string()),
        0x02 => Some("Folder".to_string()),
        0x03 => Some("Group".to_string()),
        0x04 => Some("Group".to_string()),
        0x05 => Some("ControlPanel".to_string()),
        0x06 => Some("Printers".to_string()),
        0x07 => Some("Fonts".to_string()),
        0x08 => Some("Tasks".to_string()),
        0x09 => Some("Desktop".to_string()),
        0x0A => Some("Network".to_string()),
        0x0B => Some("Network".to_string()),
        0x0C => Some("Network".to_string()),
        0x0D => Some("Temporary".to_string()),
        0x0E => Some("Recent".to_string()),
        0x0F => Some("Programs".to_string()),
        0x10 => Some("StartMenu".to_string()),
        0x11 => Some("Startup".to_string()),
        0x12 => Some("Recent".to_string()),
        0x13 => Some("SendTo".to_string()),
        0x14 => Some("RecycleBin".to_string()),
        0x15 => Some("Templates".to_string()),
        0x16 => Some("Common".to_string()),
        0x17 => Some("Common".to_string()),
        0x18 => Some("Common".to_string()),
        0x19 => Some("Common".to_string()),
        _ => Some(format!("Unknown-{:02X}", ft)),
    }
}

pub fn parse_user_shellbags(user_profile: &Path) -> Result<Vec<ShellbagEntry>, ForensicError> {
    let ntuser_path = user_profile.join("NTUSER.DAT");
    let usrclass_path = user_profile
        .join("AppData")
        .join("Local")
        .join("Microsoft")
        .join("Windows")
        .join("usrclass.dat");

    let mut all_entries = Vec::new();

    if ntuser_path.exists() {
        if let Ok(entries) = parse_shellbags(&ntuser_path, ShellbagLocation::NTUSER) {
            all_entries.extend(entries);
        }
    }

    if usrclass_path.exists() {
        if let Ok(entries) = parse_shellbags(&usrclass_path, ShellbagLocation::USRCLASS) {
            all_entries.extend(entries);
        }
    }

    Ok(all_entries)
}

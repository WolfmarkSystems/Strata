use super::scalpel::{read_prefix, DEFAULT_BINARY_MAX_BYTES};
use crate::errors::ForensicError;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ShimDatabase {
    pub entries: Vec<ShimEntry>,
    pub database_path: String,
}

#[derive(Debug, Clone)]
pub struct ShimEntry {
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub application: Option<String>,
    pub exe_name: Option<String>,
    pub installed_by: Option<String>,
    pub install_time: Option<i64>,
    pub shims: Vec<String>,
}

pub fn parse_apphelp_sdb(base_path: &Path) -> Result<ShimDatabase, ForensicError> {
    let sdb_path = base_path.join("AppPatch").join("sysmain.sdb");

    let entries = if sdb_path.exists() {
        parse_sdb_file(&sdb_path)?
    } else {
        Vec::new()
    };

    Ok(ShimDatabase {
        entries,
        database_path: sdb_path.display().to_string(),
    })
}

fn parse_sdb_file(path: &Path) -> Result<Vec<ShimEntry>, ForensicError> {
    let data = read_prefix(path, DEFAULT_BINARY_MAX_BYTES * 8)?;
    let mut entries = Vec::new();

    if data.len() < 8 {
        return Ok(entries);
    }

    if &data[0..4] == b"SDB\x00" {
        let mut offset = 8;

        while offset + 16 <= data.len() {
            let entry_type = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let entry_size = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;

            if entry_size == 0 || offset + entry_size > data.len() {
                break;
            }

            match entry_type {
                0x1001 | 0x2001 | 0x3001 => {
                    let mut entry = ShimEntry {
                        name: None,
                        vendor: None,
                        application: None,
                        exe_name: None,
                        installed_by: None,
                        install_time: None,
                        shims: Vec::new(),
                    };

                    parse_sdb_entry(&data[offset..offset + entry_size], &mut entry);
                    if entry.name.is_some()
                        || entry.application.is_some()
                        || entry.exe_name.is_some()
                    {
                        entries.push(entry);
                    }
                }
                _ => {}
            }

            offset += entry_size;
        }
    }

    Ok(entries)
}

fn parse_sdb_entry(data: &[u8], entry: &mut ShimEntry) {
    let mut offset = 8;

    while offset + 4 <= data.len() {
        let tag = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let size = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if size == 0 || offset + size > data.len() {
            break;
        }

        let value_data = &data[offset + 4..offset + size];

        match tag {
            0x1001 | 0x2001 => {
                entry.exe_name = extract_string(value_data);
            }
            0x1002 | 0x2002 => {
                entry.name = extract_string(value_data);
            }
            0x1003 | 0x2003 => {
                entry.vendor = extract_string(value_data);
            }
            0x1004 | 0x2004 => {
                entry.application = extract_string(value_data);
            }
            0x1005 => {
                entry.installed_by = extract_string(value_data);
            }
            0x1006 => {
                if value_data.len() >= 8 {
                    let ts = u64::from_le_bytes([
                        value_data[0],
                        value_data[1],
                        value_data[2],
                        value_data[3],
                        value_data[4],
                        value_data[5],
                        value_data[6],
                        value_data[7],
                    ]);
                    entry.install_time = filetime_to_unix_i64(ts);
                }
            }
            _ => {}
        }

        offset += size + 4;
    }
}

fn extract_string(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    if data.len() >= 4 && &data[0..2] == b"\x00\x00" {
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() > offset + 2 {
            let end = data[offset..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(data.len() - offset);
            let s = String::from_utf8_lossy(&data[offset..offset + end]).to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        }
    } else {
        let s = String::from_utf8_lossy(data)
            .trim_end_matches('\0')
            .to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApphelpEntry {
    pub exe_name: String,
    pub compatibility_flags: Option<u32>,
    pub compatibility_mode: Option<u32>,
    pub app_help_message: Option<String>,
    pub date: Option<i64>,
}

pub fn parse_apphelp(base_path: &Path) -> Result<Vec<ApphelpEntry>, ForensicError> {
    let mut entries = Vec::new();

    let compat_path = base_path.join("AppCompat").join("Programs");

    if !compat_path.exists() {
        return Ok(entries);
    }

    if let Ok(entries_iter) = strata_fs::read_dir(&compat_path) {
        for entry in entries_iter.flatten() {
            if entry
                .path()
                .extension()
                .map(|e| e == "dat")
                .unwrap_or(false)
            {
                if let Ok(data) = read_prefix(&entry.path(), DEFAULT_BINARY_MAX_BYTES) {
                    if let Some(apphelp) = parse_apphelp_dat(&data) {
                        entries.push(apphelp);
                    }
                }
            }
        }
    }

    Ok(entries)
}

fn parse_apphelp_dat(data: &[u8]) -> Option<ApphelpEntry> {
    if data.len() < 32 {
        return None;
    }

    let exe_name_offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let flags_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let mode_offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let help_offset = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
    let date_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

    let exe_name = if exe_name_offset > 0 && exe_name_offset < data.len() {
        String::from_utf8_lossy(&data[exe_name_offset..])
            .trim_end_matches('\0')
            .to_string()
    } else {
        return None;
    };

    let compatibility_flags = if flags_offset > 0 && flags_offset + 4 <= data.len() {
        Some(u32::from_le_bytes([
            data[flags_offset],
            data[flags_offset + 1],
            data[flags_offset + 2],
            data[flags_offset + 3],
        ]))
    } else {
        None
    };

    let compatibility_mode = if mode_offset > 0 && mode_offset + 4 <= data.len() {
        Some(u32::from_le_bytes([
            data[mode_offset],
            data[mode_offset + 1],
            data[mode_offset + 2],
            data[mode_offset + 3],
        ]))
    } else {
        None
    };

    let app_help_message = if help_offset > 0 && help_offset < data.len() {
        Some(
            String::from_utf8_lossy(&data[help_offset..])
                .trim_end_matches('\0')
                .to_string(),
        )
    } else {
        None
    };

    let date = if date_offset > 0 && date_offset + 8 <= data.len() {
        let ts = u64::from_le_bytes([
            data[date_offset],
            data[date_offset + 1],
            data[date_offset + 2],
            data[date_offset + 3],
            data[date_offset + 4],
            data[date_offset + 5],
            data[date_offset + 6],
            data[date_offset + 7],
        ]);
        filetime_to_unix_i64(ts)
    } else {
        None
    };

    Some(ApphelpEntry {
        exe_name,
        compatibility_flags,
        compatibility_mode,
        app_help_message,
        date,
    })
}

fn filetime_to_unix_i64(filetime: u64) -> Option<i64> {
    if filetime == 0 {
        return None;
    }
    let seconds = filetime / 10_000_000;
    let unix = seconds.checked_sub(11_644_473_600)?;
    i64::try_from(unix).ok()
}

#[cfg(test)]
mod tests {
    use super::filetime_to_unix_i64;

    #[test]
    fn filetime_conversion_handles_epoch_and_underflow() {
        assert_eq!(filetime_to_unix_i64(116_444_736_000_000_000), Some(0));
        assert_eq!(filetime_to_unix_i64(1), None);
        assert_eq!(filetime_to_unix_i64(0), None);
    }
}

use crate::errors::ForensicError;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct StartupEntry {
    pub name: String,
    pub path: String,
    pub location: StartupLocation,
    pub enabled: bool,
    pub registry_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StartupLocation {
    Run,
    RunOnce,
    RunServices,
    StartupFolder,
    Winlogon,
    Explorer,
    ScheduledTask,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct StartupAnalysis {
    pub entries: Vec<StartupEntry>,
    pub total_enabled: usize,
    pub total_disabled: usize,
}

pub fn parse_startup_entries(base_path: &Path) -> Result<StartupAnalysis, ForensicError> {
    let mut entries = Vec::new();
    let mut enabled_count = 0;
    let mut disabled_count = 0;

    let system_registry = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("Run");
    if let Ok(run_entries) = parse_registry_run_keys(&system_registry) {
        for (name, path, enabled) in run_entries {
            if enabled {
                enabled_count += 1;
            } else {
                disabled_count += 1;
            }
            entries.push(StartupEntry {
                name,
                path,
                location: StartupLocation::Run,
                enabled,
                registry_key: Some(system_registry.display().to_string()),
            });
        }
    }

    let run_once = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("RunOnce");
    if let Ok(run_entries) = parse_registry_run_keys(&run_once) {
        for (name, path, enabled) in run_entries {
            if enabled {
                enabled_count += 1;
            } else {
                disabled_count += 1;
            }
            entries.push(StartupEntry {
                name,
                path,
                location: StartupLocation::RunOnce,
                enabled,
                registry_key: Some(run_once.display().to_string()),
            });
        }
    }

    let run_services = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("RunServices");
    if let Ok(run_entries) = parse_registry_run_keys(&run_services) {
        for (name, path, enabled) in run_entries {
            if enabled {
                enabled_count += 1;
            } else {
                disabled_count += 1;
            }
            entries.push(StartupEntry {
                name,
                path,
                location: StartupLocation::RunServices,
                enabled,
                registry_key: Some(run_services.display().to_string()),
            });
        }
    }

    let winlogon = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows NT")
        .join("CurrentVersion")
        .join("Winlogon");
    if let Ok(winlogon_entries) = parse_winlogon_entries(&winlogon) {
        for (name, path, enabled) in winlogon_entries {
            if enabled {
                enabled_count += 1;
            } else {
                disabled_count += 1;
            }
            entries.push(StartupEntry {
                name,
                path,
                location: StartupLocation::Winlogon,
                enabled,
                registry_key: Some(winlogon.display().to_string()),
            });
        }
    }

    let explorer = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("Explorer")
        .join("StartupApproved")
        .join("Run");
    if let Ok(approved) = parse_startup_approved(&explorer) {
        for entry in entries.iter_mut() {
            if entry.location == StartupLocation::Run {
                if let Some(status) = approved.get(&entry.name) {
                    entry.enabled = *status;
                    if *status {
                        enabled_count += 1;
                    } else {
                        disabled_count += 1;
                    }
                }
            }
        }
    }

    Ok(StartupAnalysis {
        entries,
        total_enabled: enabled_count,
        total_disabled: disabled_count,
    })
}

fn parse_registry_run_keys(key_path: &Path) -> Result<Vec<(String, String, bool)>, ForensicError> {
    let mut entries = Vec::new();

    if !key_path.exists() {
        return Ok(entries);
    }

    if let Ok(entries_iter) = strata_fs::read_dir(key_path) {
        for entry in entries_iter.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            if let Ok(data) =
                super::scalpel::read_prefix(&entry.path(), super::scalpel::DEFAULT_BINARY_MAX_BYTES)
            {
                let value = extract_registry_string(&data);
                if !value.is_empty() {
                    entries.push((name, value, true));
                }
            }
        }
    }

    Ok(entries)
}

fn parse_winlogon_entries(key_path: &Path) -> Result<Vec<(String, String, bool)>, ForensicError> {
    let mut entries = Vec::new();

    if !key_path.exists() {
        return Ok(entries);
    }

    let winlogon_values = ["Userinit", "Shell", "AppSetup", "UIHost"];

    if let Ok(entries_iter) = strata_fs::read_dir(key_path) {
        for entry in entries_iter.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            if winlogon_values.iter().any(|v| name.eq_ignore_ascii_case(v)) {
                if let Ok(data) = super::scalpel::read_prefix(
                    &entry.path(),
                    super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                ) {
                    let value = extract_registry_string(&data);
                    if !value.is_empty() {
                        entries.push((name, value, true));
                    }
                }
            }
        }
    }

    Ok(entries)
}

fn parse_startup_approved(
    key_path: &Path,
) -> Result<std::collections::HashMap<String, bool>, ForensicError> {
    let mut result = std::collections::HashMap::new();

    if !key_path.exists() {
        return Ok(result);
    }

    if let Ok(entries_iter) = strata_fs::read_dir(key_path) {
        for entry in entries_iter.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            if let Ok(data) =
                super::scalpel::read_prefix(&entry.path(), super::scalpel::DEFAULT_BINARY_MAX_BYTES)
            {
                if data.len() >= 12 {
                    let enabled = data[0] != 0x03 && data[0] != 0x02;
                    result.insert(name, enabled);
                }
            }
        }
    }

    Ok(result)
}

fn extract_registry_string(data: &[u8]) -> String {
    if data.len() < 4 {
        return String::new();
    }

    if data.len() >= 8 && data[0..4] == b"\x01\x00\x00\x00"[..] {
        let offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if data.len() > offset + 2 {
            let end = data[offset..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(data.len() - offset);
            return String::from_utf8_lossy(&data[offset..offset + end]).to_string();
        }
    } else if data.len() > 2 && data[0..2] == b"\x02\x00"[..] {
        let end = data[2..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(data.len() - 2);
        return String::from_utf8_lossy(&data[2..2 + end]).to_string();
    }

    String::from_utf8_lossy(data)
        .trim_end_matches('\0')
        .to_string()
}

pub fn scan_startup_folder(path: &Path) -> Result<Vec<StartupEntry>, ForensicError> {
    let mut entries = Vec::new();

    if !path.exists() {
        return Ok(entries);
    }

    if let Ok(items) = strata_fs::read_dir(path) {
        for item in items.flatten() {
            let item_path = item.path();
            let name = item_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            let target = resolve_lnk_target(&item_path).unwrap_or(item_path.display().to_string());

            entries.push(StartupEntry {
                name,
                path: target,
                location: StartupLocation::StartupFolder,
                enabled: true,
                registry_key: Some(path.display().to_string()),
            });
        }
    }

    Ok(entries)
}

fn resolve_lnk_target(lnk_path: &Path) -> Option<String> {
    if lnk_path.extension().map(|e| e == "lnk").unwrap_or(false) {
        if let Ok(data) =
            super::scalpel::read_prefix(lnk_path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
        {
            if data.len() >= 4 && data[0..4] == b"\x4C\x00\x00\x00"[..] {
                let header_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
                if data.len() > header_size + 4 {
                    let flags = u32::from_le_bytes([
                        data[header_size],
                        data[header_size + 1],
                        data[header_size + 2],
                        data[header_size + 3],
                    ]);

                    let mut offset = header_size + 4;

                    if flags & 0x01 != 0 && data.len() > offset + 2 {
                        let id_list_size =
                            u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
                        offset += 2 + id_list_size;
                    }

                    if flags & 0x02 != 0 && data.len() > offset + 4 {
                        let _link_info_size = u32::from_le_bytes([
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                        ]) as usize;
                        if data.len() > offset + 28 {
                            let local_base_path_offset = u32::from_le_bytes([
                                data[offset + 24],
                                data[offset + 25],
                                data[offset + 26],
                                data[offset + 27],
                            ]) as usize;

                            if local_base_path_offset > 0
                                && data.len() > offset + local_base_path_offset
                            {
                                let path_start = offset + local_base_path_offset;
                                let path_end = data[path_start..]
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(data.len() - path_start);
                                return Some(
                                    String::from_utf8_lossy(
                                        &data[path_start..path_start + path_end],
                                    )
                                    .to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

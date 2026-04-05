use crate::errors::ForensicError;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct InstalledProgram {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub install_location: Option<String>,
    pub uninstall_string: Option<String>,
    pub registry_key: String,
}

#[derive(Debug, Clone)]
pub struct InstalledUpdate {
    pub hotfix_id: String,
    pub installed_on: Option<String>,
    pub installed_by: Option<String>,
    pub description: Option<String>,
}

pub fn parse_installed_programs_64bit(
    base_path: &Path,
) -> Result<Vec<InstalledProgram>, ForensicError> {
    let key_path = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("Uninstall");
    parse_uninstall_keys(&key_path)
}

pub fn parse_installed_programs_32bit(
    base_path: &Path,
) -> Result<Vec<InstalledProgram>, ForensicError> {
    let key_path = base_path
        .join("SOFTWARE")
        .join("WOW6432Node")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("Uninstall");
    parse_uninstall_keys(&key_path)
}

pub fn parse_installed_programs_user(
    base_path: &Path,
) -> Result<Vec<InstalledProgram>, ForensicError> {
    let key_path = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("Uninstall");
    parse_uninstall_keys(&key_path)
}

fn parse_uninstall_keys(key_path: &Path) -> Result<Vec<InstalledProgram>, ForensicError> {
    let mut programs = Vec::new();

    if !key_path.exists() {
        return Ok(programs);
    }

    if let Ok(entries) = strata_fs::read_dir(key_path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();

            if !entry_path.is_dir() {
                continue;
            }

            let mut program = InstalledProgram {
                name: String::new(),
                version: None,
                publisher: None,
                install_date: None,
                install_location: None,
                uninstall_string: None,
                registry_key: entry_path.display().to_string(),
            };

            if let Ok(sub_entries) = strata_fs::read_dir(&entry_path) {
                for sub_entry in sub_entries.flatten() {
                    let sub_path = sub_entry.path();
                    let file_name = sub_path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();

                    if let Ok(data) = super::scalpel::read_prefix(
                        &sub_path,
                        super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                    ) {
                        if file_name == "DisplayName" {
                            program.name = extract_registry_string(&data);
                        } else if file_name == "DisplayVersion" {
                            program.version = Some(extract_registry_string(&data));
                        } else if file_name == "Publisher" {
                            program.publisher = Some(extract_registry_string(&data));
                        } else if file_name == "InstallDate" {
                            let date = extract_registry_string(&data);
                            if date.len() == 8 {
                                program.install_date = Some(format!(
                                    "{}-{}-{}",
                                    &date[0..4],
                                    &date[4..6],
                                    &date[6..8]
                                ));
                            }
                        } else if file_name == "InstallLocation" {
                            program.install_location = Some(extract_registry_string(&data));
                        } else if file_name == "UninstallString" {
                            program.uninstall_string = Some(extract_registry_string(&data));
                        }
                    }
                }
            }

            if !program.name.is_empty() {
                programs.push(program);
            }
        }
    }

    Ok(programs)
}

pub fn parse_installed_updates(base_path: &Path) -> Result<Vec<InstalledUpdate>, ForensicError> {
    let mut updates = Vec::new();

    let key_path = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("Component Based Servicing")
        .join("Packages");

    if !key_path.exists() {
        return Ok(updates);
    }

    if let Ok(entries) = strata_fs::read_dir(&key_path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();

            if !entry_path.is_dir() {
                continue;
            }

            let mut update = InstalledUpdate {
                hotfix_id: String::new(),
                installed_on: None,
                installed_by: None,
                description: None,
            };

            let key_name = entry_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            update.hotfix_id = key_name.clone();

            if let Ok(state_path) = strata_fs::read_dir(entry_path.join("Servicing")) {
                for state_entry in state_path.flatten() {
                    let state_file = state_entry.path();
                    let file_name = state_file
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();

                    if file_name == "State" {
                        if let Ok(data) = super::scalpel::read_prefix(
                            &state_file,
                            super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                        ) {
                            if data.len() >= 4 {
                                let state =
                                    u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                                if state != 0 {
                                    if let Ok(meta) = strata_fs::metadata(&entry_path) {
                                        if let Ok(modified) = meta.modified() {
                                            let timestamp = modified
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .map(|d| d.as_secs() as i64)
                                                .unwrap_or(0);
                                            let datetime =
                                                time::OffsetDateTime::from_unix_timestamp(
                                                    timestamp,
                                                )
                                                .unwrap_or(time::OffsetDateTime::now_utc());
                                            update.installed_on = Some(format!(
                                                "{:04}-{:02}-{:02}",
                                                datetime.year(),
                                                datetime.month() as u8,
                                                datetime.day()
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if !update.hotfix_id.is_empty() {
                updates.push(update);
            }
        }
    }

    Ok(updates)
}

fn extract_registry_string(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    if data.len() >= 4 && &data[0..4] == b"\x01\x00\x00\x00" {
        let offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if data.len() > offset + 2 {
            let end = data[offset..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(data.len() - offset);
            return String::from_utf8_lossy(&data[offset..offset + end]).to_string();
        }
    }

    String::from_utf8_lossy(data)
        .trim_end_matches('\0')
        .to_string()
}

pub fn get_all_installed_programs(
    base_path: &Path,
) -> Result<Vec<InstalledProgram>, ForensicError> {
    let mut all_programs = Vec::new();

    if let Ok(programs) = parse_installed_programs_64bit(base_path) {
        all_programs.extend(programs);
    }

    if let Ok(programs) = parse_installed_programs_32bit(base_path) {
        all_programs.extend(programs);
    }

    all_programs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    all_programs.dedup_by(|a, b| a.name == b.name && a.version == b.version);

    Ok(all_programs)
}

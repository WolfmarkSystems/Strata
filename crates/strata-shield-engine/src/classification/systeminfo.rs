use crate::errors::ForensicError;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub computer_name: Option<String>,
    pub username: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub os_architecture: Option<String>,
    pub install_date: Option<i64>,
    pub last_boot_time: Option<i64>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub domain: Option<String>,
    pub domain_role: Option<String>,
}

pub fn get_system_info(base_path: &Path) -> Result<SystemInfo, ForensicError> {
    let mut info = SystemInfo {
        computer_name: None,
        username: None,
        os_name: None,
        os_version: None,
        os_architecture: None,
        install_date: None,
        last_boot_time: None,
        timezone: None,
        locale: None,
        domain: None,
        domain_role: None,
    };

    let control_set = find_current_control_set(base_path)?;

    let computer_name_path = base_path
        .join("SYSTEM")
        .join(&control_set)
        .join("Control")
        .join("ComputerName")
        .join("ComputerName");
    if let Ok(data) = super::scalpel::read_prefix(
        &computer_name_path,
        super::scalpel::DEFAULT_BINARY_MAX_BYTES,
    ) {
        info.computer_name = extract_registry_string(&data);
    }

    let version_path = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows NT")
        .join("CurrentVersion");
    if let Ok(entries) = strata_fs::read_dir(&version_path) {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if let Ok(data) =
                super::scalpel::read_prefix(&entry.path(), super::scalpel::DEFAULT_BINARY_MAX_BYTES)
            {
                match file_name.as_str() {
                    "ProductName" => info.os_name = extract_registry_string(&data),
                    "CurrentBuild" | "CurrentVersion" => {
                        if info.os_version.is_none() {
                            info.os_version = extract_registry_string(&data);
                        }
                    }
                    "InstallationType" => info.os_architecture = extract_registry_string(&data),
                    "InstallDate" => {
                        if let Some(date_str) = extract_registry_string(&data) {
                            if let Ok(timestamp) = date_str.parse::<i64>() {
                                info.install_date = Some(timestamp);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let timezone_path = base_path
        .join("SYSTEM")
        .join(&control_set)
        .join("Control")
        .join("TimeZoneInformation");
    if let Ok(entries) = strata_fs::read_dir(&timezone_path) {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name == "TimeZoneKeyName" || file_name == "StandardName" {
                if let Ok(data) = super::scalpel::read_prefix(
                    &entry.path(),
                    super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                ) {
                    info.timezone = extract_registry_string(&data);
                }
            }
        }
    }

    let control_panel_path = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("International");
    if let Ok(entries) = strata_fs::read_dir(&control_panel_path) {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name == "LocaleName" || file_name == "Locale" {
                if let Ok(data) = super::scalpel::read_prefix(
                    &entry.path(),
                    super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                ) {
                    info.locale = extract_registry_string(&data);
                }
            }
        }
    }

    let domain_path = base_path
        .join("SYSTEM")
        .join(&control_set)
        .join("Services")
        .join("Tcpip")
        .join("Parameters");
    if let Ok(entries) = strata_fs::read_dir(&domain_path) {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name == "Domain" || file_name == "NV Domain" {
                if let Ok(data) = super::scalpel::read_prefix(
                    &entry.path(),
                    super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                ) {
                    info.domain = extract_registry_string(&data);
                }
            }
        }
    }

    info.username = std::env::var("USERNAME").ok();

    info.last_boot_time = get_last_boot_time(base_path)?;

    Ok(info)
}

fn find_current_control_set(base_path: &Path) -> Result<String, ForensicError> {
    let select_path = base_path.join("SYSTEM").join("Select");

    if !select_path.exists() {
        return Ok("ControlSet001".to_string());
    }

    if let Ok(entries) = strata_fs::read_dir(&select_path) {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name == "Current" {
                if let Ok(data) = super::scalpel::read_prefix(
                    &entry.path(),
                    super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                ) {
                    if let Some(value) = extract_registry_string(&data) {
                        if let Ok(num) = value.parse::<u32>() {
                            return Ok(format!("ControlSet{:03}", num));
                        }
                    }
                }
            }
        }
    }

    Ok("ControlSet001".to_string())
}

fn get_last_boot_time(base_path: &Path) -> Result<Option<i64>, ForensicError> {
    let control_set = find_current_control_set(base_path)?;

    let perfdata_path = base_path
        .join("SYSTEM")
        .join(&control_set)
        .join("Services")
        .join("EventLog")
        .join("System");

    if !perfdata_path.exists() {
        return Ok(None);
    }

    let boot_time_path = perfdata_path.join("BootStart");
    if boot_time_path.exists() {
        if let Ok(meta) = strata_fs::metadata(&boot_time_path) {
            if let Ok(modified) = meta.modified() {
                return Ok(Some(
                    modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0),
                ));
            }
        }
    }

    Ok(None)
}

fn extract_registry_string(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    if data.len() >= 4 && &data[0..4] == b"\x01\x00\x00\x00" {
        let offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
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
pub struct AntivirusInfo {
    pub name: Option<String>,
    pub enabled: bool,
    pub signatures_date: Option<i64>,
    pub signatures_version: Option<String>,
    pub real_time_protection: bool,
    pub last_scan: Option<i64>,
}

pub fn get_antivirus_info(base_path: &Path) -> Result<Vec<AntivirusInfo>, ForensicError> {
    let mut av_list = Vec::new();

    let security_path = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows")
        .join("SecurityCenter")
        .join("AntiVirus");

    if security_path.exists() {
        if let Ok(entries) = strata_fs::read_dir(&security_path) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let mut av = AntivirusInfo {
                        name: None,
                        enabled: false,
                        signatures_date: None,
                        signatures_version: None,
                        real_time_protection: false,
                        last_scan: None,
                    };

                    if let Ok(sub_entries) = strata_fs::read_dir(entry.path()) {
                        for sub_entry in sub_entries.flatten() {
                            let file_name = sub_entry.file_name().to_string_lossy().to_string();
                            let sub_path = sub_entry.path();
                            if let Ok(data) = super::scalpel::read_prefix(
                                &sub_path,
                                super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                            ) {
                                match file_name.as_str() {
                                    "DisplayName" | "Name" => {
                                        av.name = extract_registry_string(&data)
                                    }
                                    "Enabled" => {
                                        av.enabled = extract_registry_string(&data)
                                            .map(|s| s == "1")
                                            .unwrap_or(false)
                                    }
                                    "AvSigVersion" => {
                                        av.signatures_version = extract_registry_string(&data)
                                    }
                                    "AvSigDate" => {
                                        if let Some(date_str) = extract_registry_string(&data) {
                                            av.signatures_date = parse_av_date(&date_str);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    if av.name.is_some() {
                        av_list.push(av);
                    }
                }
            }
        }
    }

    Ok(av_list)
}

fn parse_av_date(date_str: &str) -> Option<i64> {
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() >= 3 {
        let year: i64 = parts[0].parse().ok()?;
        let month: i64 = parts[1].parse().ok()?;
        let day: i64 = parts[2].parse().ok()?;

        let mut days =
            (year - 1970) * 365 + (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400;
        let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        for m in 1..month {
            if m <= month_days.len() as i64 {
                days += month_days[m as usize - 1] as i64;
            }
        }
        Some(days + day - 1)
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct FirewallInfo {
    pub enabled: bool,
    pub domain_enabled: bool,
    pub public_enabled: bool,
    pub private_enabled: bool,
}

pub fn get_firewall_info(base_path: &Path) -> Result<FirewallInfo, ForensicError> {
    let control_set = find_current_control_set(base_path)?;

    let fw_path = base_path
        .join("SYSTEM")
        .join(&control_set)
        .join("Services")
        .join("SharedAccess")
        .join("Parameters")
        .join("FirewallPolicy");

    let mut info = FirewallInfo {
        enabled: false,
        domain_enabled: false,
        public_enabled: false,
        private_enabled: false,
    };

    let profiles = ["DomainProfile", "PublicProfile", "StandardProfile"];

    for profile in profiles {
        let profile_path = fw_path.join(profile);
        if profile_path.exists() {
            if let Ok(entries) = strata_fs::read_dir(&profile_path) {
                for entry in entries.flatten() {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    if file_name == "EnableFirewall" {
                        if let Ok(data) = super::scalpel::read_prefix(
                            &entry.path(),
                            super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                        ) {
                            if let Some(value) = extract_registry_string(&data) {
                                let enabled = value == "1";
                                match profile {
                                    "DomainProfile" => {
                                        info.domain_enabled = enabled;
                                        if enabled {
                                            info.enabled = true;
                                        }
                                    }
                                    "PublicProfile" => {
                                        info.public_enabled = enabled;
                                        if enabled {
                                            info.enabled = true;
                                        }
                                    }
                                    "StandardProfile" => {
                                        info.private_enabled = enabled;
                                        if enabled {
                                            info.enabled = true;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(info)
}

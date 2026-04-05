use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use crate::errors::ForensicError;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: Option<String>,
    pub auth: Option<String>,
    pub cipher: Option<String>,
    pub channel: Option<u32>,
    pub signal: Option<i32>,
    pub last_connected: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct WifiProfile {
    pub ssid: String,
    pub authentication: Option<String>,
    pub encryption: Option<String>,
    pub key_material: Option<String>,
    pub last_updated: Option<i64>,
}

pub fn parse_wifi_profiles(system_registry: &Path) -> Result<Vec<WifiProfile>, ForensicError> {
    let mut profiles = Vec::new();

    let wifi_keys_path = system_registry
        .join("Microsoft")
        .join("Windows NT")
        .join("CurrentVersion")
        .join("NetworkList")
        .join("Signatures")
        .join("Unmanaged");

    if !wifi_keys_path.exists() {
        return Ok(profiles);
    }

    if let Ok(entries) = strata_fs::read_dir(&wifi_keys_path) {
        for entry in entries.flatten() {
            let profile = parse_wifi_profile_entry(&entry.path());
            profiles.push(profile);
        }
    }

    let managed_path = system_registry
        .join("Microsoft")
        .join("Windows NT")
        .join("CurrentVersion")
        .join("NetworkList")
        .join("Signatures")
        .join("Managed");

    if managed_path.exists() {
        if let Ok(entries) = strata_fs::read_dir(&managed_path) {
            for entry in entries.flatten() {
                let profile = parse_wifi_profile_entry(&entry.path());
                profiles.push(profile);
            }
        }
    }

    Ok(profiles)
}

fn parse_wifi_profile_entry(path: &Path) -> WifiProfile {
    let mut ssid = String::new();
    let mut authentication = None;
    let mut encryption = None;
    let key_material = None;
    let last_updated = None;

    if let Ok(data) = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) {
        let mut offset = 0;

        while offset + 8 < data.len() {
            let value_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
            let data_size = u32::from_le_bytes([
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
            ]) as usize;

            if value_type == 0 && data_size > 0 && offset + 8 + data_size <= data.len() {
                let value_data = &data[offset + 8..offset + 8 + data_size];
                let name = String::from_utf8_lossy(value_data)
                    .trim_matches('\0')
                    .to_string();

                if name.contains("SSID") && value_data.len() > 4 {
                    let ssid_len = value_data[0] as usize;
                    if ssid_len > 0 && ssid_len < value_data.len() - 1 {
                        ssid = String::from_utf8_lossy(&value_data[1..1 + ssid_len]).to_string();
                    }
                }
            } else if value_type == 2 && data_size > 0 && offset + 8 + data_size <= data.len() {
                let value_data = &data[offset + 8..offset + 8 + data_size];
                let name = String::from_utf8_lossy(value_data)
                    .trim_matches('\0')
                    .to_string();

                if name.contains("Auth") || name.contains("Encryption") {
                    if let Some(key) = value_data.get(2..) {
                        let cleaned = String::from_utf8_lossy(key).trim_matches('\0').to_string();
                        if name.contains("Auth") {
                            authentication = Some(cleaned);
                        } else {
                            encryption = Some(cleaned);
                        }
                    }
                }
            }

            offset += 8 + data_size;
        }
    }

    WifiProfile {
        ssid,
        authentication,
        encryption,
        key_material,
        last_updated,
    }
}

pub fn parse_wlan_interface(system_registry: &Path) -> Result<Vec<WifiNetwork>, ForensicError> {
    let mut networks = Vec::new();

    let interfaces_path = system_registry
        .join("Microsoft")
        .join("Windows NT")
        .join("CurrentVersion")
        .join("NetworkList")
        .join("Interfaces");

    if !interfaces_path.exists() {
        return Ok(networks);
    }

    if let Ok(entries) = strata_fs::read_dir(&interfaces_path) {
        for entry in entries.flatten() {
            let guid = entry.file_name().to_string_lossy().to_string();
            let interface_path = entry.path();

            if let Ok(interface_data) = strata_fs::read_dir(&interface_path) {
                for iface_entry in interface_data.flatten() {
                    if let Ok(data) = super::scalpel::read_prefix(
                        &iface_entry.path(),
                        super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                    ) {
                        let network = parse_interface_data(&data, &guid);
                        if !network.ssid.is_empty() {
                            networks.push(network);
                        }
                    }
                }
            }
        }
    }

    Ok(networks)
}

fn parse_interface_data(data: &[u8], _guid: &str) -> WifiNetwork {
    let mut ssid = String::new();
    let mut bssid = None;
    let mut last_connected = None;

    let mut offset = 0;

    while offset + 4 < data.len() {
        let signature = &data[offset..offset + 4];

        if signature == b"\x00\x00\x00\x00" || signature == b"\x01\x00\x00\x00" {
            let entry_size = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;

            if entry_size > 0 && offset + 8 + entry_size <= data.len() && entry_size > 32 {
                let entry_data = &data[offset + 8..offset + 8 + entry_size];

                let bssid_bytes = &entry_data[0..6];
                if bssid_bytes.iter().all(|&b| b != 0) {
                    bssid = Some(format!(
                        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        bssid_bytes[0],
                        bssid_bytes[1],
                        bssid_bytes[2],
                        bssid_bytes[3],
                        bssid_bytes[4],
                        bssid_bytes[5]
                    ));
                }

                let profile_offset = 24;
                if entry_data.len() > profile_offset + 2 {
                    let profile_len = entry_data[profile_offset] as usize;
                    if entry_data.len() > profile_offset + 1 + profile_len {
                        ssid = String::from_utf8_lossy(
                            &entry_data[profile_offset + 1..profile_offset + 1 + profile_len],
                        )
                        .to_string();
                    }
                }

                let timestamp_offset = entry_data.len() - 8;
                if entry_data.len() > timestamp_offset {
                    let timestamp = u64::from_le_bytes([
                        entry_data[timestamp_offset],
                        entry_data[timestamp_offset + 1],
                        entry_data[timestamp_offset + 2],
                        entry_data[timestamp_offset + 3],
                        entry_data[timestamp_offset + 4],
                        entry_data[timestamp_offset + 5],
                        entry_data[timestamp_offset + 6],
                        entry_data[timestamp_offset + 7],
                    ]);
                    if timestamp > 1000000000 {
                        last_connected = Some((timestamp / 10_000_000 - 11644473600) as i64);
                    }
                }
            }

            offset += 8 + entry_size;
        } else {
            offset += 1;
        }
    }

    WifiNetwork {
        ssid,
        bssid,
        auth: None,
        cipher: None,
        channel: None,
        signal: None,
        last_connected,
    }
}

pub fn parse_dns_cache(path: &Path) -> Result<Vec<DnsRecord>, ForensicError> {
    let mut records = Vec::new();

    if !path.exists() {
        return Ok(records);
    }

    if let Ok(content) = read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let record_type = parts[0];
                let name = parts[1];

                let ttl = if parts.len() > 2 {
                    parts[2].parse().ok()
                } else {
                    None
                };

                let data = if parts.len() > 4 {
                    Some(parts[4..].join(" "))
                } else {
                    None
                };

                records.push(DnsRecord {
                    name: name.to_string(),
                    record_type: record_type.to_string(),
                    ttl,
                    data,
                });
            }
        }
    }

    Ok(records)
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub ttl: Option<u32>,
    pub data: Option<String>,
}

pub fn parse_arp_cache() -> Result<Vec<ArpEntry>, ForensicError> {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut entries = Vec::new();

    #[cfg(windows)]
    {
        use std::process::Command;
        let output = Command::new("arp").arg("-a").output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.starts_with("Interface:") || line.starts_with("---") || line.is_empty() {
                    continue;
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let ip = parts[0].to_string();
                    let mac = parts[1].to_string();

                    if mac != "ff-ff-ff-ff-ff-ff" && mac != "000000000000" {
                        entries.push(ArpEntry { ip, mac });
                    }
                }
            }
        }
    }

    Ok(entries)
}

#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
}

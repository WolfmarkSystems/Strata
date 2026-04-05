use crate::errors::ForensicError;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct WindowsService {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub status: ServiceStatus,
    pub start_type: StartType,
    pub path: Option<String>,
    pub started_by: Option<String>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ServiceStatus {
    Running,
    Stopped,
    Paused,
    StartPending,
    StopPending,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum StartType {
    Automatic,
    AutomaticDelayed,
    Manual,
    Disabled,
    Boot,
    System,
    Unknown,
}

pub fn parse_services(base_path: &Path) -> Result<Vec<WindowsService>, ForensicError> {
    let mut services = Vec::new();

    let services_path = base_path
        .join("SYSTEM")
        .join("CurrentControlSet")
        .join("Services");

    if !services_path.exists() {
        return Ok(services);
    }

    if let Ok(entries) = strata_fs::read_dir(&services_path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();

            if !entry_path.is_dir() {
                continue;
            }

            let service = parse_service_entry(&entry_path)?;
            if !service.name.is_empty() {
                services.push(service);
            }
        }
    }

    Ok(services)
}

fn parse_service_entry(service_path: &Path) -> Result<WindowsService, ForensicError> {
    let mut service = WindowsService {
        name: service_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        display_name: String::new(),
        description: None,
        status: ServiceStatus::Unknown,
        start_type: StartType::Unknown,
        path: None,
        started_by: None,
        dependencies: Vec::new(),
    };

    if let Ok(entries) = strata_fs::read_dir(service_path) {
        for entry in entries.flatten() {
            let entry_file = entry.path();
            let file_name = entry_file
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            if let Ok(data) =
                super::scalpel::read_prefix(&entry_file, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
            {
                match file_name.as_str() {
                    "DisplayName" => {
                        service.display_name = extract_registry_string(&data);
                    }
                    "Description" => {
                        service.description = Some(extract_registry_string(&data));
                    }
                    "Start" => {
                        service.start_type = parse_start_type(&data);
                    }
                    "ImagePath" => {
                        service.path = Some(extract_registry_string(&data));
                    }
                    "ObjectName" => {
                        service.started_by = Some(extract_registry_string(&data));
                    }
                    "Type" => {
                        service.status = parse_service_type(&data);
                    }
                    "DependOnService" => {
                        service.dependencies = extract_multi_string(&data);
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(service)
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

fn extract_multi_string(data: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if byte == 0 {
            if !current.is_empty() {
                results.push(current.clone());
                current.clear();
            }
        } else {
            current.push(byte as char);
        }
    }

    if !current.is_empty() {
        results.push(current);
    }

    results
}

fn parse_start_type(data: &[u8]) -> StartType {
    if data.len() < 4 {
        return StartType::Unknown;
    }

    let start_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    match start_type {
        0 => StartType::Boot,
        1 => StartType::System,
        2 => StartType::Automatic,
        3 => StartType::Manual,
        4 => StartType::Disabled,
        _ => StartType::Unknown,
    }
}

fn parse_service_type(data: &[u8]) -> ServiceStatus {
    if data.len() < 4 {
        return ServiceStatus::Unknown;
    }

    let service_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    match service_type {
        16 => ServiceStatus::Running,
        32 => ServiceStatus::StartPending,
        64 => ServiceStatus::StopPending,
        128 => ServiceStatus::Paused,
        _ => ServiceStatus::Unknown,
    }
}

pub fn get_running_services(services: &[WindowsService]) -> Vec<&WindowsService> {
    services
        .iter()
        .filter(|s| matches!(s.status, ServiceStatus::Running))
        .collect()
}

pub fn get_auto_start_services(services: &[WindowsService]) -> Vec<&WindowsService> {
    services
        .iter()
        .filter(|s| {
            matches!(
                s.start_type,
                StartType::Automatic | StartType::AutomaticDelayed
            )
        })
        .collect()
}

pub fn get_disabled_services(services: &[WindowsService]) -> Vec<&WindowsService> {
    services
        .iter()
        .filter(|s| matches!(s.start_type, StartType::Disabled))
        .collect()
}

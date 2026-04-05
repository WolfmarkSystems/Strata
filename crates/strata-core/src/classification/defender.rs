use std::env;
use std::path::{Path, PathBuf};

use crate::errors::ForensicError;

use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use super::{regdefendercfg, windowsdefender};

#[derive(Debug, Clone, Default)]
pub struct AntivirusProduct {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub enabled: bool,
    pub real_time_protection: bool,
    pub last_update: Option<u64>,
    pub product_type: AvProductType,
}

#[derive(Debug, Clone, Default)]
pub enum AvProductType {
    #[default]
    Antivirus,
    Antispyware,
    Firewall,
    DeviceControl,
}

pub fn get_av_products() -> Result<Vec<AntivirusProduct>, ForensicError> {
    let status = get_defender_status()?;
    let mut out = vec![AntivirusProduct {
        name: "Windows Defender".to_string(),
        publisher: "Microsoft".to_string(),
        version: "".to_string(),
        enabled: status.enabled,
        real_time_protection: status.real_time_protection,
        last_update: status.last_scan,
        product_type: AvProductType::Antivirus,
    }];

    let fw = regdefendercfg::get_windows_firewall_config();
    if fw.domain_profile || fw.private_profile || fw.public_profile {
        out.push(AntivirusProduct {
            name: "Windows Firewall".to_string(),
            publisher: "Microsoft".to_string(),
            version: "".to_string(),
            enabled: true,
            real_time_protection: false,
            last_update: None,
            product_type: AvProductType::Firewall,
        });
    }

    Ok(out)
}

pub fn get_defender_status() -> Result<DefenderStatus, ForensicError> {
    let cfg = regdefendercfg::get_windows_defender_config();
    let wd = windowsdefender::check_windows_defender_status()?;
    Ok(DefenderStatus {
        enabled: wd.enabled,
        real_time_protection: cfg.realtime_protection,
        behavior_monitoring: cfg.behavior_monitoring,
        script_scanning: cfg.script_scanning,
        cloud_protection: windowsdefender::get_defender_settings()?.cloud_delivery,
        tamper_protection: cfg.realtime_protection,
        signature_age: 0,
        last_scan: latest_scan_end_time(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct DefenderStatus {
    pub enabled: bool,
    pub real_time_protection: bool,
    pub behavior_monitoring: bool,
    pub script_scanning: bool,
    pub cloud_protection: bool,
    pub tamper_protection: bool,
    pub signature_age: u32,
    pub last_scan: Option<u64>,
}

pub fn get_defender_quarantined_items() -> Result<Vec<QuarantinedItem>, ForensicError> {
    Ok(parse_quarantine_log(&quarantine_log_path()))
}

#[derive(Debug, Clone, Default)]
pub struct QuarantinedItem {
    pub threat_name: String,
    pub file_path: String,
    pub quarantine_time: u64,
    pub original_threat_level: String,
}

pub fn get_defender_scan_history() -> Result<Vec<ScanHistory>, ForensicError> {
    Ok(parse_scan_history_log(&scan_history_path()))
}

#[derive(Debug, Clone, Default)]
pub struct ScanHistory {
    pub scan_type: ScanType,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub threats_found: u32,
    pub threats_resolved: u32,
    pub scan_result: ScanResult,
}

#[derive(Debug, Clone, Default)]
pub enum ScanType {
    #[default]
    Quick,
    Full,
    Custom,
}

#[derive(Debug, Clone, Default)]
pub enum ScanResult {
    #[default]
    Unknown,
    Completed,
    Cancelled,
    Failed,
}

pub fn get_defender_exclusions() -> Result<Vec<ExclusionEntry>, ForensicError> {
    let values = regdefendercfg::get_defender_exclusions();
    Ok(values
        .into_iter()
        .map(|value| ExclusionEntry {
            exclusion_type: infer_exclusion_type(&value),
            value,
        })
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct ExclusionEntry {
    pub exclusion_type: ExclusionType,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub enum ExclusionType {
    #[default]
    Path,
    Extension,
    Process,
}

fn parse_quarantine_log(path: &Path) -> Vec<QuarantinedItem> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 2) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = if trimmed.contains('|') {
            trimmed.split('|').collect()
        } else {
            trimmed.split(',').collect()
        };
        if parts.len() < 3 {
            continue;
        }
        out.push(QuarantinedItem {
            threat_name: parts[0].trim().to_string(),
            file_path: parts[1].trim().to_string(),
            quarantine_time: parts[2].trim().parse::<u64>().unwrap_or(0),
            original_threat_level: parts
                .get(3)
                .map(|v| v.trim())
                .unwrap_or("Unknown")
                .to_string(),
        });
    }
    out
}

fn parse_scan_history_log(path: &Path) -> Vec<ScanHistory> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 2) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = if trimmed.contains('|') {
            trimmed.split('|').collect()
        } else {
            trimmed.split(',').collect()
        };
        if parts.len() < 4 {
            continue;
        }

        let scan_type = match parts[0].trim().to_ascii_lowercase().as_str() {
            "full" => ScanType::Full,
            "custom" => ScanType::Custom,
            _ => ScanType::Quick,
        };
        let result = match parts[3].trim().to_ascii_lowercase().as_str() {
            "completed" | "success" => ScanResult::Completed,
            "cancelled" => ScanResult::Cancelled,
            "failed" => ScanResult::Failed,
            _ => ScanResult::Unknown,
        };

        out.push(ScanHistory {
            scan_type,
            start_time: parts[1].trim().parse::<u64>().unwrap_or(0),
            end_time: parts.get(2).and_then(|v| v.trim().parse::<u64>().ok()),
            threats_found: parts
                .get(4)
                .and_then(|v| v.trim().parse::<u32>().ok())
                .unwrap_or(0),
            threats_resolved: parts
                .get(5)
                .and_then(|v| v.trim().parse::<u32>().ok())
                .unwrap_or(0),
            scan_result: result,
        });
    }
    out
}

fn infer_exclusion_type(value: &str) -> ExclusionType {
    let lower = value.to_ascii_lowercase();
    if lower.ends_with(".exe") || lower.contains('\\') {
        ExclusionType::Process
    } else if lower.starts_with('.') {
        ExclusionType::Extension
    } else {
        ExclusionType::Path
    }
}

fn latest_scan_end_time() -> Option<u64> {
    parse_scan_history_log(&scan_history_path())
        .into_iter()
        .filter_map(|row| row.end_time.or(Some(row.start_time)))
        .max()
}

fn quarantine_log_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_DEFENDER_QUARANTINE") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("defender")
        .join("quarantine.log")
}

fn scan_history_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_DEFENDER_SCAN_HISTORY") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("defender")
        .join("scan_history.log")
}

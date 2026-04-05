use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;

use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use crate::errors::ForensicError;

#[derive(Debug, Clone, Default)]
pub struct SetupApiLog {
    pub timestamp: u64,
    pub event_type: String,
    pub device_id: Option<String>,
    pub driver_name: Option<String>,
}

pub fn parse_setup_api_log(path: &str) -> Result<Vec<SetupApiLog>, ForensicError> {
    let content = match read_text_prefix(path.as_ref(), DEFAULT_TEXT_MAX_BYTES * 4) {
        Ok(v) => v,
        Err(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    let mut current_ts: u64 = 0;
    let mut current_device: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(ts) = parse_setupapi_timestamp(trimmed) {
            current_ts = ts;
        }
        if let Some(device_id) = extract_device_id(trimmed) {
            current_device = Some(device_id);
        }

        if trimmed.contains("Device Install")
            || trimmed.starts_with("dvi:")
            || trimmed.starts_with("inf:")
            || trimmed.starts_with("sto:")
        {
            out.push(SetupApiLog {
                timestamp: current_ts,
                event_type: classify_event_type(trimmed),
                device_id: current_device.clone(),
                driver_name: extract_driver_name(trimmed),
            });
        }
    }

    Ok(out)
}

pub fn get_installed_drivers() -> Result<Vec<DriverInfo>, ForensicError> {
    let mut by_name: BTreeMap<String, DriverInfo> = BTreeMap::new();

    for event in parse_setup_api_log(&setupapi_log_path().to_string_lossy())? {
        if let Some(driver_name) = event.driver_name {
            if driver_name.is_empty() {
                continue;
            }
            by_name.entry(driver_name.clone()).or_insert(DriverInfo {
                name: driver_name,
                version: None,
                provider: None,
                date: if event.timestamp > 0 {
                    Some(event.timestamp)
                } else {
                    None
                },
            });
        }
    }

    Ok(by_name.into_values().collect())
}

#[derive(Debug, Clone, Default)]
pub struct DriverInfo {
    pub name: String,
    pub version: Option<String>,
    pub provider: Option<String>,
    pub date: Option<u64>,
}

fn setupapi_log_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_SETUPAPI_LOG") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("setupapi")
        .join("setupapi.dev.log")
}

fn parse_setupapi_timestamp(line: &str) -> Option<u64> {
    // setupapi often contains: ">>>  Section start 2025/01/10 10:35:20.123"
    if !line.to_ascii_lowercase().contains("section start") {
        return None;
    }
    let mut parts = line.split_whitespace().rev();
    let time = parts.next()?;
    let date = parts.next()?;
    unix_from_setupapi_date_time(date, time)
}

fn unix_from_setupapi_date_time(date: &str, time: &str) -> Option<u64> {
    let d: Vec<&str> = date.split('/').collect();
    let t: Vec<&str> = time.split(':').collect();
    if d.len() != 3 || t.len() < 2 {
        return None;
    }
    let year = d[0].parse::<i32>().ok()?;
    let month = d[1].parse::<u32>().ok()?;
    let day = d[2].parse::<u32>().ok()?;
    let hour = t[0].parse::<u32>().ok()?;
    let minute = t[1].parse::<u32>().ok()?;
    let sec_token = t.get(2).copied().unwrap_or("0");
    let second = sec_token
        .split('.')
        .next()
        .unwrap_or("0")
        .parse::<u32>()
        .ok()?;
    unix_from_ymd_hms(year, month, day, hour, minute, second)
}

fn unix_from_ymd_hms(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<u64> {
    if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let y = year - ((month <= 2) as i32);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i32;
    let d = day as i32;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days as i64 * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64;
    if secs < 0 {
        None
    } else {
        Some(secs as u64)
    }
}

fn extract_device_id(line: &str) -> Option<String> {
    if let Some(start) = line.find("USB\\") {
        return Some(line[start..].trim_matches(&['[', ']', ' '][..]).to_string());
    }
    if let Some(start) = line.find("PCI\\") {
        return Some(line[start..].trim_matches(&['[', ']', ' '][..]).to_string());
    }
    None
}

fn extract_driver_name(line: &str) -> Option<String> {
    if let Some(idx) = line.to_ascii_lowercase().find(".inf") {
        let prefix = &line[..=idx + 3];
        let token = prefix
            .split_whitespace()
            .last()
            .unwrap_or("")
            .trim_matches(&['[', ']', '"'][..]);
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    None
}

fn classify_event_type(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if lower.contains("device install") {
        "device-install".to_string()
    } else if lower.starts_with("dvi:") {
        "device-info".to_string()
    } else if lower.starts_with("inf:") {
        "driver-inf".to_string()
    } else if lower.starts_with("sto:") {
        "driver-store".to_string()
    } else {
        "setupapi".to_string()
    }
}

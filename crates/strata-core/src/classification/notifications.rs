use std::env;
use std::path::PathBuf;

use serde_json::Value;
use tracing::warn;

use crate::errors::ForensicError;

#[derive(Debug, Clone, Default)]
pub struct WindowsNotification {
    pub app_id: String,
    pub title: String,
    pub message: String,
    pub timestamp: u64,
}

pub fn get_notification_history() -> Result<Vec<WindowsNotification>, ForensicError> {
    let path = notifications_path();
    let data = match super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "[classification::notifications] notification history read failed, returning empty: {}",
                e
            );
            return Ok(Vec::new());
        }
    };
    parse_toast_notifications(&data)
}

pub fn parse_toast_notifications(data: &[u8]) -> Result<Vec<WindowsNotification>, ForensicError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(value) = serde_json::from_slice::<Value>(data) {
        return Ok(parse_from_json_value(&value));
    }

    let content = String::from_utf8_lossy(data);
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
        out.push(WindowsNotification {
            timestamp: parse_timestamp(parts[0]),
            app_id: parts[1].trim().to_string(),
            title: parts[2].trim().to_string(),
            message: parts[3].trim().to_string(),
        });
    }
    Ok(out)
}

fn parse_from_json_value(value: &Value) -> Vec<WindowsNotification> {
    let Some(items) = value.as_array() else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for item in items {
        let app_id = item
            .get("app_id")
            .and_then(Value::as_str)
            .or_else(|| item.get("appId").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        let title = item
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let message = item
            .get("message")
            .and_then(Value::as_str)
            .or_else(|| item.get("body").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        let timestamp = item
            .get("timestamp")
            .and_then(value_to_unix)
            .or_else(|| item.get("timestamp_utc").and_then(value_to_unix))
            .unwrap_or(0);

        if app_id.is_empty() && title.is_empty() && message.is_empty() {
            continue;
        }
        out.push(WindowsNotification {
            app_id,
            title,
            message,
            timestamp,
        });
    }
    out
}

fn value_to_unix(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let s = v.as_str()?;
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    parse_iso8601_basic(s)
}

fn parse_timestamp(raw: &str) -> u64 {
    raw.trim()
        .parse::<u64>()
        .ok()
        .or_else(|| parse_iso8601_basic(raw))
        .unwrap_or(0)
}

fn parse_iso8601_basic(raw: &str) -> Option<u64> {
    // Supports "YYYY-MM-DDTHH:MM:SSZ" and "YYYY-MM-DD HH:MM:SS".
    let normalized = raw.trim().trim_end_matches('Z').replace('T', " ");
    let mut it = normalized.split(' ');
    let date = it.next()?;
    let time = it.next()?;
    let d: Vec<&str> = date.split('-').collect();
    let t: Vec<&str> = time.split(':').collect();
    if d.len() != 3 || t.len() < 2 {
        return None;
    }
    let year = d[0].parse::<i32>().ok()?;
    let month = d[1].parse::<u32>().ok()?;
    let day = d[2].parse::<u32>().ok()?;
    let hour = t[0].parse::<u32>().ok()?;
    let minute = t[1].parse::<u32>().ok()?;
    let second = t.get(2).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
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

fn notifications_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_NOTIFICATIONS_JSON") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("notifications")
        .join("toast_notifications.json")
}

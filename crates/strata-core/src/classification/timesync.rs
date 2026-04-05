use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct TimeSource {
    pub source_name: String,
    pub source_type: TimeSourceType,
    pub stratum: u8,
    pub last_sync: Option<u64>,
    pub offset: i64,
    pub poll_interval: u64,
}

#[derive(Debug, Clone, Default)]
pub enum TimeSourceType {
    #[default]
    Local,
    NTP,
    Manual,
    Domain,
}

pub fn get_time_sources() -> Result<Vec<TimeSource>, ForensicError> {
    let Some(items) = load(path("FORENSIC_TIME_SOURCES", "time_sources.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| TimeSource {
            source_name: s(&v, &["source_name", "name"]),
            source_type: source_type_enum(s(&v, &["source_type", "type"])),
            stratum: n(&v, &["stratum"]) as u8,
            last_sync: opt_n(&v, &["last_sync", "last_sync_time"]),
            offset: i(&v, &["offset", "offset_ms"]),
            poll_interval: n(&v, &["poll_interval", "poll_interval_seconds"]),
        })
        .filter(|x| !x.source_name.is_empty() || x.stratum > 0)
        .collect())
}

pub fn get_time_sync_history() -> Result<Vec<TimeSyncEvent>, ForensicError> {
    let Some(items) = load(path("FORENSIC_TIME_SYNC_HISTORY", "time_sync_history.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| TimeSyncEvent {
            timestamp: n(&v, &["timestamp", "time"]),
            source: s(&v, &["source"]),
            offset_ms: i(&v, &["offset_ms", "offset"]),
            round_trip_ms: n(&v, &["round_trip_ms", "rtt_ms"]),
            success: b(&v, &["success", "ok"]),
        })
        .filter(|x| x.timestamp > 0 || !x.source.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct TimeSyncEvent {
    pub timestamp: u64,
    pub source: String,
    pub offset_ms: i64,
    pub round_trip_ms: u64,
    pub success: bool,
}

pub fn get_system_time_info() -> Result<SystemTimeInfo, ForensicError> {
    Ok(SystemTimeInfo {
        current_time: 0,
        time_zone: "".to_string(),
        daylight_saving: false,
        last_boot: None,
    })
}

#[derive(Debug, Clone, Default)]
pub struct SystemTimeInfo {
    pub current_time: u64,
    pub time_zone: String,
    pub daylight_saving: bool,
    pub last_boot: Option<u64>,
}

pub fn get_ntp_statistics() -> Result<NtpStatistics, ForensicError> {
    Ok(NtpStatistics {
        packets_sent: 0,
        packets_received: 0,
        packet_loss: 0.0,
        average_offset: 0,
    })
}

#[derive(Debug, Clone, Default)]
pub struct NtpStatistics {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packet_loss: f64,
    pub average_offset: i64,
}

pub fn check_time_anomalies() -> Result<Vec<TimeAnomaly>, ForensicError> {
    let Some(items) = load(path("FORENSIC_TIME_ANOMALIES", "time_anomalies.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| TimeAnomaly {
            timestamp: n(&v, &["timestamp", "time"]),
            anomaly_type: s(&v, &["anomaly_type", "type"]),
            description: s(&v, &["description", "message"]),
        })
        .filter(|x| x.timestamp > 0 || !x.anomaly_type.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct TimeAnomaly {
    pub timestamp: u64,
    pub anomaly_type: String,
    pub description: String,
}

fn source_type_enum(value: String) -> TimeSourceType {
    match value.to_ascii_lowercase().as_str() {
        "ntp" => TimeSourceType::NTP,
        "manual" => TimeSourceType::Manual,
        "domain" => TimeSourceType::Domain,
        _ => TimeSourceType::Local,
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("timesync").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let v: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = v.as_array() {
        Some(items.clone())
    } else if v.is_object() {
        v.get("items")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| v.get("results").and_then(Value::as_array).cloned())
            .or_else(|| Some(vec![v]))
    } else {
        None
    }
}

fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}

fn n(v: &Value, keys: &[&str]) -> u64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return x as u64;
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return n;
            }
        }
    }
    0
}

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return Some(x as u64);
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

fn i(v: &Value, keys: &[&str]) -> i64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            if x <= i64::MAX as u64 {
                return x as i64;
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<i64>() {
                return n;
            }
        }
    }
    0
}

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}

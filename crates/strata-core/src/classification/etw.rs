use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::{Path, PathBuf};
use tracing::warn;

#[derive(Debug, Clone, Default)]
pub struct EtwProvider {
    pub name: String,
    pub guid: String,
    pub enabled: bool,
    pub level: u8,
    pub keywords: u64,
}

pub fn get_etw_providers() -> Result<Vec<EtwProvider>, ForensicError> {
    let Some(items) = load_array(path("FORENSIC_ETW_PROVIDERS", "providers.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| EtwProvider {
            name: s(&v, &["name", "provider_name"]),
            guid: s(&v, &["guid", "provider_id"]),
            enabled: b(&v, &["enabled"]),
            level: n(&v, &["level"]) as u8,
            keywords: n(&v, &["keywords"]),
        })
        .filter(|x| !x.name.is_empty() || !x.guid.is_empty())
        .collect())
}

pub fn get_active_etw_sessions() -> Result<Vec<EtwSession>, ForensicError> {
    let Some(items) = load_array(path("FORENSIC_ETW_SESSIONS", "sessions.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| EtwSession {
            name: s(&v, &["name", "session_name"]),
            session_type: s(&v, &["session_type", "type"]),
            log_file_mode: n(&v, &["log_file_mode", "logfile_mode"]) as u32,
            buffer_size: n(&v, &["buffer_size"]) as u32,
            max_file_size: n(&v, &["max_file_size"]),
            provider_count: n(&v, &["provider_count"]) as u32,
        })
        .filter(|x| !x.name.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct EtwSession {
    pub name: String,
    pub session_type: String,
    pub log_file_mode: u32,
    pub buffer_size: u32,
    pub max_file_size: u64,
    pub provider_count: u32,
}

pub fn get_ntfs_log_info(_volume: &str) -> Result<EtwLogInfo, ForensicError> {
    let Some(v) = load_object(path("FORENSIC_ETW_NTFS_LOG", "ntfs_log.json")) else {
        return Ok(EtwLogInfo {
            log_size: 0,
            file_records: 0,
            last_checkpoint: None,
        });
    };
    Ok(EtwLogInfo {
        log_size: n(&v, &["log_size"]),
        file_records: n(&v, &["file_records"]),
        last_checkpoint: opt_n(&v, &["last_checkpoint"]),
    })
}

#[derive(Debug, Clone, Default)]
pub struct EtwLogInfo {
    pub log_size: u64,
    pub file_records: u64,
    pub last_checkpoint: Option<u64>,
}

pub fn get_transaction_log_info() -> Result<TransactionLogInfo, ForensicError> {
    let Some(v) = load_object(path("FORENSIC_ETW_TRANSACTION_LOG", "transaction_log.json")) else {
        return Ok(TransactionLogInfo {
            total_size: 0,
            active_size: 0,
            oldest_lsn: 0,
        });
    };
    Ok(TransactionLogInfo {
        total_size: n(&v, &["total_size"]),
        active_size: n(&v, &["active_size"]),
        oldest_lsn: n(&v, &["oldest_lsn"]),
    })
}

#[derive(Debug, Clone, Default)]
pub struct TransactionLogInfo {
    pub total_size: u64,
    pub active_size: u64,
    pub oldest_lsn: u64,
}

pub fn parse_etl_file(etl_path: &str) -> Result<Vec<EtlEvent>, ForensicError> {
    let data = match super::scalpel::read_prefix(
        Path::new(etl_path),
        super::scalpel::DEFAULT_BINARY_MAX_BYTES,
    ) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "[classification::etw] ETL file read failed, returning empty: {}",
                e
            );
            return Ok(Vec::new());
        }
    };
    let json: Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "[classification::etw] ETL JSON parse failed, returning empty: {}",
                e
            );
            return Ok(Vec::new());
        }
    };
    let Some(items) = json.as_array() else {
        return Ok(Vec::new());
    };
    Ok(items
        .iter()
        .map(|v| EtlEvent {
            timestamp: n(v, &["timestamp", "time"]),
            provider_id: s(v, &["provider_id", "provider", "guid"]),
            level: n(v, &["level"]) as u8,
            opcode: n(v, &["opcode"]) as u8,
            message: s(v, &["message", "summary"]),
        })
        .filter(|x| x.timestamp > 0 || !x.provider_id.is_empty() || !x.message.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct EtlEvent {
    pub timestamp: u64,
    pub provider_id: String,
    pub level: u8,
    pub opcode: u8,
    pub message: String,
}

pub fn get_boot_performance_data() -> Result<BootPerformance, ForensicError> {
    let Some(v) = load_object(path("FORENSIC_ETW_BOOT_PERF", "boot_performance.json")) else {
        return Ok(BootPerformance {
            boot_time: 0,
            shutdown_time: 0,
            boot_duration_ms: 0,
            shutdown_duration_ms: 0,
        });
    };
    Ok(BootPerformance {
        boot_time: n(&v, &["boot_time"]),
        shutdown_time: n(&v, &["shutdown_time"]),
        boot_duration_ms: n(&v, &["boot_duration_ms"]),
        shutdown_duration_ms: n(&v, &["shutdown_duration_ms"]),
    })
}

#[derive(Debug, Clone, Default)]
pub struct BootPerformance {
    pub boot_time: u64,
    pub shutdown_time: u64,
    pub boot_duration_ms: u64,
    pub shutdown_duration_ms: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("etw").join(file))
}

fn load_array(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
}

fn load_object(path: PathBuf) -> Option<Value> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let value: Value = serde_json::from_slice(&data).ok()?;
    if value.is_object() {
        Some(value)
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
    opt_n(v, keys).unwrap_or(0)
}

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}

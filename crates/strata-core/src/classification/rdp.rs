use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32, parse_reg_u64,
};

#[derive(Debug, Clone)]
pub struct RdpRemoteAccessRecord {
    pub target_host: Option<String>,
    pub client_address: Option<String>,
    pub username: Option<String>,
    pub user_sid: Option<String>,
    pub session_id: Option<String>,
    pub start_time_unix: Option<i64>,
    pub end_time_unix: Option<i64>,
    pub timestamp_unix: Option<i64>,
    pub timestamp_utc: Option<String>,
    pub timestamp_precision: String,
    pub duration_seconds: Option<i64>,
    pub source_kind: Option<String>,
    pub process_path: Option<String>,
    pub source_path: Option<String>,
    pub source_record_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpInputShape {
    Missing,
    Empty,
    Directory,
    JsonArray,
    JsonObject,
    CsvText,
    LineText,
    Unknown,
}

impl RdpInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::Directory => "directory",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::CsvText => "csv-text",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_rdp_input_shape(path: &Path) -> RdpInputShape {
    if !path.exists() {
        return RdpInputShape::Missing;
    }
    if path.is_dir() {
        return RdpInputShape::Directory;
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return RdpInputShape::Unknown;
    };
    if bytes.is_empty() {
        return RdpInputShape::Empty;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return RdpInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return RdpInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return RdpInputShape::JsonObject;
    }
    let first = trimmed
        .lines()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if first.contains("target_host")
        || first.contains("host")
        || first.contains("client_address")
        || first.contains("session")
    {
        return RdpInputShape::CsvText;
    }
    RdpInputShape::LineText
}

pub fn parse_rdp_records_from_path(path: &Path, limit: usize) -> Vec<RdpRemoteAccessRecord> {
    if !path.exists() || limit == 0 {
        return Vec::new();
    }

    let mut rows = if path.is_dir() {
        parse_rdp_dir(path, limit)
    } else {
        parse_rdp_file(path)
    };
    if rows.is_empty() {
        rows = parse_rdp_text_fallback(path);
    }

    let mut seen = BTreeSet::<String>::new();
    rows.retain(|row| {
        let key = format!(
            "{}|{}|{}|{}|{}",
            row.target_host.clone().unwrap_or_default(),
            row.timestamp_unix
                .map(|v| v.to_string())
                .unwrap_or_default(),
            row.username.clone().unwrap_or_default(),
            row.client_address.clone().unwrap_or_default(),
            row.source_record_id.clone().unwrap_or_default()
        );
        seen.insert(key)
    });

    rows.sort_by(|a, b| {
        b.timestamp_unix
            .is_some()
            .cmp(&a.timestamp_unix.is_some())
            .then_with(|| {
                b.timestamp_unix
                    .unwrap_or_default()
                    .cmp(&a.timestamp_unix.unwrap_or_default())
            })
            .then_with(|| {
                a.target_host
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(b.target_host.as_deref().unwrap_or_default())
            })
            .then_with(|| {
                a.session_id
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(b.session_id.as_deref().unwrap_or_default())
            })
    });
    rows.truncate(limit);
    rows
}

pub fn parse_rdp_text_fallback(path: &Path) -> Vec<RdpRemoteAccessRecord> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_rdp_csv_or_lines(&content)
}

fn parse_rdp_dir(path: &Path, limit: usize) -> Vec<RdpRemoteAccessRecord> {
    let mut out = Vec::new();
    let Ok(entries) = strata_fs::read_dir(path) else {
        return out;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let mut nested = parse_rdp_dir(&p, limit.saturating_sub(out.len()));
            out.append(&mut nested);
        } else {
            let mut rows = parse_rdp_file(&p);
            out.append(&mut rows);
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn parse_rdp_file(path: &Path) -> Vec<RdpRemoteAccessRecord> {
    let Ok(bytes) = strata_fs::read(path) else {
        return Vec::new();
    };
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        return parse_rdp_rows_json_value(&value);
    }
    parse_rdp_csv_or_lines(String::from_utf8_lossy(&bytes).as_ref())
}

fn parse_rdp_rows_json_value(value: &Value) -> Vec<RdpRemoteAccessRecord> {
    let rows = if let Some(arr) = value.as_array() {
        arr.clone()
    } else if let Some(obj) = value.as_object() {
        obj.get("records")
            .and_then(|v| v.as_array())
            .or_else(|| obj.get("sessions").and_then(|v| v.as_array()))
            .or_else(|| obj.get("connections").and_then(|v| v.as_array()))
            .or_else(|| obj.get("events").and_then(|v| v.as_array()))
            .or_else(|| obj.get("data").and_then(|v| v.as_array()))
            .cloned()
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let mut out = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else {
            continue;
        };

        let target_host = obj
            .get("target_host")
            .and_then(|v| v.as_str())
            .or_else(|| obj.get("host").and_then(|v| v.as_str()))
            .or_else(|| obj.get("server").and_then(|v| v.as_str()))
            .or_else(|| obj.get("destination").and_then(|v| v.as_str()))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        let start = parse_ts(
            obj.get("start_time_unix")
                .or_else(|| obj.get("start_time"))
                .or_else(|| obj.get("connect_time"))
                .or_else(|| obj.get("timestamp_unix"))
                .or_else(|| obj.get("timestamp"))
                .or_else(|| obj.get("occurred_utc"))
                .or_else(|| obj.get("timestamp_utc")),
        );
        let end = parse_ts(
            obj.get("end_time_unix")
                .or_else(|| obj.get("end_time"))
                .or_else(|| obj.get("disconnect_time")),
        );
        let (timestamp_unix, timestamp_utc, timestamp_precision) = start.clone();
        let duration_seconds = match (start.0, end.0) {
            (Some(a), Some(b)) if b >= a => Some(b - a),
            _ => obj
                .get("duration_seconds")
                .or_else(|| obj.get("duration"))
                .and_then(value_to_i64),
        };

        out.push(RdpRemoteAccessRecord {
            target_host,
            client_address: obj
                .get("client_address")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("source_ip").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            username: obj
                .get("username")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("user").and_then(|v| v.as_str()))
                .map(normalize_username),
            user_sid: obj
                .get("user_sid")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("sid").and_then(|v| v.as_str()))
                .map(normalize_sid),
            session_id: obj
                .get("session_id")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("id").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            start_time_unix: start.0,
            end_time_unix: end.0,
            timestamp_unix,
            timestamp_utc,
            timestamp_precision,
            duration_seconds,
            source_kind: obj
                .get("source_kind")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("source").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty()),
            process_path: obj
                .get("process_path")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("process").and_then(|v| v.as_str()))
                .map(normalize_path),
            source_path: obj
                .get("source_path")
                .and_then(|v| v.as_str())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            source_record_id: obj
                .get("source_record_id")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("record_id").and_then(|v| v.as_str()))
                .or_else(|| obj.get("event_id").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
        });
    }

    out
}

fn parse_rdp_csv_or_lines(content: &str) -> Vec<RdpRemoteAccessRecord> {
    let mut out = Vec::new();
    let mut lines = content.lines();
    let first = lines.next().unwrap_or_default();
    let first_lc = first.to_ascii_lowercase();
    if first.contains(',')
        && (first_lc.contains("target_host")
            || first_lc.contains("host")
            || first_lc.contains("session")
            || first_lc.contains("client_address"))
    {
        let headers = first
            .split(',')
            .map(|v| v.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let cols = trimmed.split(',').map(|v| v.trim()).collect::<Vec<_>>();
            if cols.is_empty() {
                continue;
            }
            let get_col = |name: &str| -> Option<&str> {
                headers
                    .iter()
                    .position(|h| h == name)
                    .and_then(|idx| cols.get(idx).copied())
            };

            let ts = parse_ts_str(
                get_col("timestamp_unix")
                    .or_else(|| get_col("timestamp"))
                    .or_else(|| get_col("connect_time"))
                    .or_else(|| get_col("start_time"))
                    .or_else(|| get_col("occurred_utc"))
                    .unwrap_or_default(),
            );
            out.push(RdpRemoteAccessRecord {
                target_host: get_col("target_host")
                    .or_else(|| get_col("host"))
                    .or_else(|| get_col("server"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                client_address: get_col("client_address")
                    .or_else(|| get_col("source_ip"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                username: get_col("username")
                    .or_else(|| get_col("user"))
                    .map(normalize_username),
                user_sid: get_col("user_sid")
                    .or_else(|| get_col("sid"))
                    .map(normalize_sid),
                session_id: get_col("session_id")
                    .or_else(|| get_col("id"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                start_time_unix: ts.0,
                end_time_unix: get_col("end_time_unix")
                    .or_else(|| get_col("disconnect_time"))
                    .and_then(|v| parse_ts_str(v).0),
                timestamp_unix: ts.0,
                timestamp_utc: ts.1,
                timestamp_precision: ts.2,
                duration_seconds: get_col("duration_seconds").and_then(|v| v.parse::<i64>().ok()),
                source_kind: get_col("source_kind")
                    .or_else(|| get_col("source"))
                    .map(|v| v.to_ascii_lowercase())
                    .filter(|v| !v.is_empty()),
                process_path: get_col("process_path")
                    .or_else(|| get_col("process"))
                    .map(normalize_path),
                source_path: get_col("source_path")
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                source_record_id: get_col("source_record_id")
                    .or_else(|| get_col("record_id"))
                    .or_else(|| get_col("event_id"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
            });
        }
        return out;
    }

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((host, ts)) = trimmed.split_once('|') {
            let parsed = parse_ts_str(ts);
            out.push(RdpRemoteAccessRecord {
                target_host: Some(host.trim().to_string()).filter(|v| !v.is_empty()),
                client_address: None,
                username: None,
                user_sid: None,
                session_id: None,
                start_time_unix: parsed.0,
                end_time_unix: None,
                timestamp_unix: parsed.0,
                timestamp_utc: parsed.1,
                timestamp_precision: parsed.2,
                duration_seconds: None,
                source_kind: None,
                process_path: None,
                source_path: None,
                source_record_id: None,
            });
        }
    }

    out
}

fn parse_ts(value: Option<&Value>) -> (Option<i64>, Option<String>, String) {
    let Some(v) = value else {
        return (None, None, "none".to_string());
    };
    if let Some(n) = value_to_i64(v) {
        return normalize_epochish_ts(n);
    }
    if let Some(s) = v.as_str() {
        return parse_ts_str(s);
    }
    (None, None, "none".to_string())
}

fn parse_ts_str(value: &str) -> (Option<i64>, Option<String>, String) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return (None, None, "none".to_string());
    }
    if let Ok(num) = trimmed.parse::<i64>() {
        return normalize_epochish_ts(num);
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        let ts = dt.timestamp();
        return (Some(ts), Some(ts_to_utc(ts)), "seconds".to_string());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        let ts = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc)
            .timestamp();
        return (Some(ts), Some(ts_to_utc(ts)), "seconds".to_string());
    }
    (None, None, "none".to_string())
}

fn normalize_epochish_ts(value: i64) -> (Option<i64>, Option<String>, String) {
    if value <= 0 {
        return (None, None, "none".to_string());
    }
    let (ts, precision) = if value > 10_000_000_000 {
        (value / 1_000, "milliseconds".to_string())
    } else {
        (value, "seconds".to_string())
    };
    (Some(ts), Some(ts_to_utc(ts)), precision)
}

fn ts_to_utc(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}

fn value_to_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
        .or_else(|| value.as_str().and_then(|v| v.trim().parse::<i64>().ok()))
}

fn normalize_sid(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn normalize_username(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_path(value: &str) -> String {
    value
        .trim()
        .replace('/', "\\")
        .replace("\\\\?\\", "")
        .trim_end_matches('\\')
        .to_string()
}

#[derive(Debug, Clone, Default)]
pub struct RdpSession {
    pub id: String,
    pub target_host: String,
    pub connect_time: u64,
    pub disconnect_time: Option<u64>,
    pub duration: u64,
    pub client_name: String,
    pub client_address: String,
}

pub fn get_rdp_connections() -> Result<Vec<RdpConnection>, ForensicError> {
    let records = load_reg_records(&default_reg_path("rdp.reg"));
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("terminal server client\\servers")
            || p.contains("terminal server client\\default")
    }) {
        let host = key_leaf(&record.path);
        if host.is_empty() {
            continue;
        }
        let user = record
            .values
            .get("UsernameHint")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| {
                record
                    .values
                    .get("UserName")
                    .and_then(|v| decode_reg_string(v))
            });

        out.push(RdpConnection {
            name: host.clone(),
            host,
            port: record
                .values
                .get("PortNumber")
                .and_then(|v| parse_reg_u32(v))
                .and_then(|v| u16::try_from(v).ok())
                .unwrap_or(3389),
            username: user,
            last_connected: record
                .values
                .get("LastConnected")
                .and_then(|v| parse_reg_u64(v))
                .or_else(|| {
                    record
                        .values
                        .get("Timestamp")
                        .and_then(|v| parse_reg_u64(v))
                }),
        });
    }

    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct RdpConnection {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub last_connected: Option<u64>,
}

pub fn get_rdp_settings() -> Result<RdpSettings, ForensicError> {
    let records = load_reg_records(&default_reg_path("rdp.reg"));
    let mut settings = RdpSettings {
        nla_enabled: true,
        network_level_authentication: true,
        port: 3389,
    };

    for record in &records {
        let p = record.path.to_ascii_lowercase();
        if p.contains("terminal server") {
            if let Some(v) = record
                .values
                .get("fDenyTSConnections")
                .and_then(|v| parse_reg_u32(v))
            {
                settings.nla_enabled = v == 0;
            }
            if let Some(v) = record
                .values
                .get("UserAuthentication")
                .and_then(|v| parse_reg_u32(v))
            {
                settings.network_level_authentication = v != 0;
            }
        }
        if p.contains("winstations\\rdp-tcp") {
            if let Some(v) = record
                .values
                .get("PortNumber")
                .and_then(|v| parse_reg_u32(v))
                .and_then(|v| u16::try_from(v).ok())
            {
                settings.port = v;
            }
        }
    }

    Ok(settings)
}

#[derive(Debug, Clone, Default)]
pub struct RdpSettings {
    pub nla_enabled: bool,
    pub network_level_authentication: bool,
    pub port: u16,
}

pub fn get_rdp_port_status() -> Result<bool, ForensicError> {
    let cfg = get_rdp_settings()?;
    Ok(cfg.nla_enabled && cfg.port > 0)
}

pub fn get_rdp_saved_credentials() -> Result<Vec<SavedCredential>, ForensicError> {
    let records = load_reg_records(&default_reg_path("rdp.reg"));
    let mut out = Vec::new();

    for record in &records {
        let p = record.path.to_ascii_lowercase();
        if !p.contains("credentials") && !p.contains("credman") {
            continue;
        }

        for (name, raw) in &record.values {
            let decoded = decode_reg_string(raw).unwrap_or_default();
            let target = if name.to_ascii_lowercase().contains("termsrv/")
                || decoded.to_ascii_lowercase().contains("termsrv/")
            {
                if name.to_ascii_lowercase().contains("termsrv/") {
                    name.clone()
                } else {
                    decoded.clone()
                }
            } else {
                continue;
            };

            out.push(SavedCredential {
                target,
                username: record
                    .values
                    .get("UserName")
                    .and_then(|v| decode_reg_string(v))
                    .unwrap_or_default(),
                last_used: record
                    .values
                    .get("LastWritten")
                    .and_then(|v| parse_reg_u64(v)),
            });
        }
    }

    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct SavedCredential {
    pub target: String,
    pub username: String,
    pub last_used: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_rdp_input_shape_supports_directory_json_csv() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("rdp");
        let json = temp.path().join("rdp.json");
        let csv = temp.path().join("rdp.csv");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(
            &json,
            r#"[{"target_host":"srv1","timestamp":1700044001,"username":"Analyst","user_sid":"s-1-5-21"}]"#,
        )
        .expect("json");
        std::fs::write(
            &csv,
            "target_host,client_address,timestamp,username\nsrv2,10.0.0.2,1700044002,investigator\n",
        )
        .expect("csv");

        assert_eq!(detect_rdp_input_shape(&dir), RdpInputShape::Directory);
        assert_eq!(detect_rdp_input_shape(&json), RdpInputShape::JsonArray);
        assert_eq!(detect_rdp_input_shape(&csv), RdpInputShape::CsvText);
    }

    #[test]
    fn parse_rdp_records_from_path_parses_json_rows() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("rdp.json");
        std::fs::write(
            &path,
            r#"[{"target_host":"srv1","timestamp":1700045001,"username":"Analyst","user_sid":"s-1-5-21","process_path":"C:/Windows/System32/mstsc.exe"}]"#,
        )
        .expect("write");

        let rows = parse_rdp_records_from_path(&path, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target_host.as_deref(), Some("srv1"));
        assert_eq!(rows[0].timestamp_unix, Some(1_700_045_001));
        assert_eq!(rows[0].username.as_deref(), Some("analyst"));
        assert_eq!(rows[0].user_sid.as_deref(), Some("S-1-5-21"));
        assert_eq!(
            rows[0].process_path.as_deref(),
            Some("C:\\Windows\\System32\\mstsc.exe")
        );
    }

    #[test]
    fn parse_rdp_text_fallback_handles_partial_rows() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("rdp.txt");
        std::fs::write(&path, "srv1|1700045002\nsrv2|\n").expect("write");

        let rows = parse_rdp_text_fallback(&path);
        assert!(rows.len() >= 2);
        assert!(rows
            .iter()
            .any(|r| r.target_host.as_deref() == Some("srv1")));
    }
}

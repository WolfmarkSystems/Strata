//! EVTX event log parsing helpers.

use chrono::{DateTime, Utc};
#[cfg(target_os = "windows")]
use evtx::{EvtxParser, ParserSettings};
#[cfg(target_os = "windows")]
use serde_json::Value;
#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct EvtxEvent {
    pub timestamp: Option<DateTime<Utc>>,
    pub event_id: u32,
    pub channel: String,
    pub provider: String,
    pub computer: String,
    pub level: String,
    pub record_id: Option<u64>,
    pub summary: String,
}

#[cfg(target_os = "windows")]
pub fn parse_evtx_bytes(
    path_hint: &str,
    bytes: &[u8],
    max_events: usize,
) -> Result<Vec<EvtxEvent>, String> {
    if bytes.len() < 8 {
        return Err("EVTX bytes too small".to_string());
    }

    let temp_path = temp_evtx_path(path_hint);
    std::fs::write(&temp_path, bytes).map_err(|e| format!("temp write failed: {}", e))?;
    let parsed = parse_evtx_file(&temp_path, max_events);
    let _ = std::fs::remove_file(&temp_path);
    parsed
}

#[cfg(not(target_os = "windows"))]
pub fn parse_evtx_bytes(
    _path_hint: &str,
    _bytes: &[u8],
    _max_events: usize,
) -> Result<Vec<EvtxEvent>, String> {
    Err("EVTX parsing is only supported on Windows".to_string())
}

#[cfg(target_os = "windows")]
pub fn parse_evtx_file(path: &Path, max_events: usize) -> Result<Vec<EvtxEvent>, String> {
    let parser = EvtxParser::from_path(path).map_err(|e| format!("evtx open failed: {}", e))?;
    let mut parser = parser.with_configuration(
        ParserSettings::default()
            .num_threads(0)
            .separate_json_attributes(true),
    );

    let mut events = Vec::new();
    for record in parser.records_json_value().take(max_events) {
        let Ok(record) = record else {
            continue;
        };
        if let Some(event) = parse_record(&record.data) {
            events.push(event);
        }
    }
    Ok(events)
}

pub fn is_high_value_event_id(event_id: u32) -> bool {
    matches!(
        event_id,
        4624 | 4625 | 4634 | 4672 | 4688 | 4697 | 4720 | 4726 | 4732 | 4733 | 7045 | 1102
    )
}

pub fn is_suspicious_event(event: &EvtxEvent) -> bool {
    if matches!(
        event.event_id,
        4625 | 4688 | 4697 | 4720 | 4726 | 7045 | 1102
    ) {
        return true;
    }
    let summary = event.summary.to_lowercase();
    summary.contains("mimikatz")
        || summary.contains("meterpreter")
        || summary.contains("cobalt")
        || summary.contains("clear")
        || summary.contains("disable")
        || summary.contains("tamper")
}

#[cfg(target_os = "windows")]
fn parse_record(data: &Value) -> Option<EvtxEvent> {
    let system = find_path(data, &["Event.System", "System"])?;

    let event_id = extract_u32(system.get("EventID")).unwrap_or(0);
    let channel = extract_string(system.get("Channel")).unwrap_or_else(|| "-".to_string());
    let provider = system
        .get("Provider")
        .and_then(|v| {
            if let Some(name) = v.get("#attributes").and_then(|a| a.get("Name")) {
                extract_string(Some(name))
            } else if let Some(name) = v.get("Name") {
                extract_string(Some(name))
            } else {
                extract_string(Some(v))
            }
        })
        .unwrap_or_else(|| "-".to_string());
    let computer = extract_string(system.get("Computer")).unwrap_or_else(|| "-".to_string());
    let level = extract_string(system.get("Level")).unwrap_or_else(|| "-".to_string());
    let record_id = extract_u64(system.get("EventRecordID"));

    let timestamp = system
        .get("TimeCreated")
        .and_then(|v| {
            v.get("#attributes")
                .and_then(|a| a.get("SystemTime"))
                .or_else(|| v.get("SystemTime"))
        })
        .and_then(|v| extract_string(Some(v)))
        .and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        });

    let summary = build_summary(data);

    Some(EvtxEvent {
        timestamp,
        event_id,
        channel,
        provider,
        computer,
        level,
        record_id,
        summary,
    })
}

#[cfg(target_os = "windows")]
fn find_path<'a>(root: &'a Value, paths: &[&str]) -> Option<&'a Value> {
    for path in paths {
        let mut cursor = root;
        let mut ok = true;
        for seg in path.split('.') {
            match cursor.get(seg) {
                Some(next) => cursor = next,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return Some(cursor);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn extract_string(value: Option<&Value>) -> Option<String> {
    let value = value?;
    match value {
        Value::String(s) => Some(s.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Object(map) => {
            if let Some(v) = map.get("#text") {
                return extract_string(Some(v));
            }
            if let Some(v) = map.get("Name") {
                return extract_string(Some(v));
            }
            if let Some(v) = map.get("#value") {
                return extract_string(Some(v));
            }
            None
        }
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn extract_u32(value: Option<&Value>) -> Option<u32> {
    let value = value?;
    match value {
        Value::Number(n) => n.as_u64().and_then(|v| u32::try_from(v).ok()),
        Value::String(s) => s.parse::<u32>().ok(),
        Value::Object(map) => map.get("#text").and_then(|v| extract_u32(Some(v))),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn extract_u64(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse::<u64>().ok(),
        Value::Object(map) => map.get("#text").and_then(|v| extract_u64(Some(v))),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn build_summary(root: &Value) -> String {
    let mut parts = Vec::new();

    if let Some(event_data) = find_path(
        root,
        &["Event.EventData", "Event.UserData", "Event.RenderingInfo"],
    ) {
        match event_data {
            Value::Object(map) => {
                for (key, value) in map {
                    if let Some(s) = extract_string(Some(value)) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            parts.push(format!("{}={}", key, trimmed));
                        }
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    if let Some(s) = extract_string(Some(item)) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            parts.push(trimmed.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if parts.is_empty() {
        return "Event data unavailable".to_string();
    }

    let joined = parts.join(" | ");
    if joined.len() > 600 {
        format!("{}...", &joined[..600])
    } else {
        joined
    }
}

#[cfg(target_os = "windows")]
fn temp_evtx_path(path_hint: &str) -> PathBuf {
    let mut safe = path_hint.replace([':', '\\', '/', ' '], "_");
    if safe.len() > 64 {
        safe.truncate(64);
    }
    std::env::temp_dir().join(format!("strata_evtx_{}_{}.evtx", std::process::id(), safe))
}

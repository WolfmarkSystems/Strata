//! IOT-5 — Smart lock + alarm-system artifacts.
//!
//! Covers August / Yale / Schlage Encode / Kwikset Halo event logs
//! and the generic alarm-system arm/disarm trail (ADT / Ring Alarm /
//! SimpliSafe). All vendors converge on a JSON event-list shape on
//! their mobile apps, so this module normalises to one
//! `SmartLockEvent` / `AlarmSystemEvent` pair of records.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmartLockEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub lock_name: String,
    pub lock_location: Option<String>,
    pub event_type: String,
    pub actor: Option<String>,
    pub method: String,
    pub successful: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlarmSystemEvent {
    pub timestamp: DateTime<Utc>,
    pub system_name: String,
    pub event_type: String,
    pub zone: Option<String>,
    pub actor: Option<String>,
}

pub fn parse_lock_events(json: &str) -> Vec<SmartLockEvent> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = v
        .get("events")
        .and_then(|x| x.as_array())
        .or_else(|| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for entry in arr {
        let ts = entry
            .get("timestamp")
            .and_then(|x| x.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        out.push(SmartLockEvent {
            event_id: entry
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
            timestamp: ts,
            lock_name: entry
                .get("lock")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
            lock_location: entry
                .get("location")
                .and_then(|x| x.as_str())
                .map(String::from),
            event_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Unknown")
                .into(),
            actor: entry
                .get("actor")
                .and_then(|x| x.as_str())
                .map(String::from),
            method: entry
                .get("method")
                .and_then(|x| x.as_str())
                .unwrap_or("Unknown")
                .into(),
            successful: entry
                .get("successful")
                .and_then(|x| x.as_bool())
                .unwrap_or(true),
        });
    }
    out
}

pub fn parse_alarm_events(json: &str) -> Vec<AlarmSystemEvent> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = v
        .get("events")
        .and_then(|x| x.as_array())
        .or_else(|| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for entry in arr {
        let ts = entry
            .get("timestamp")
            .and_then(|x| x.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        out.push(AlarmSystemEvent {
            timestamp: ts,
            system_name: entry
                .get("system")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
            event_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Unknown")
                .into(),
            zone: entry.get("zone").and_then(|x| x.as_str()).map(String::from),
            actor: entry
                .get("actor")
                .and_then(|x| x.as_str())
                .map(String::from),
        });
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_august_unlock_event() {
        let json = r#"[{"id":"e1","timestamp":"2026-04-10T08:00:00Z","lock":"Front Door",
            "location":"front","type":"Unlock","actor":"alice","method":"App","successful":true}]"#;
        let e = parse_lock_events(json);
        assert_eq!(e[0].event_type, "Unlock");
        assert_eq!(e[0].method, "App");
        assert!(e[0].successful);
    }

    #[test]
    fn parses_failed_keypad_attempt() {
        let json = r#"[{"id":"e2","timestamp":"2026-04-10T08:05:00Z","lock":"Front Door",
            "type":"CodeEntered","method":"Keypad","successful":false}]"#;
        let e = parse_lock_events(json);
        assert!(!e[0].successful);
    }

    #[test]
    fn parses_alarm_disarm_event() {
        let json = r#"{"events":[
            {"timestamp":"2026-04-10T08:00:00Z","system":"SimpliSafe","type":"Disarm",
             "actor":"alice"}
        ]}"#;
        let e = parse_alarm_events(json);
        assert_eq!(e[0].event_type, "Disarm");
        assert_eq!(e[0].actor.as_deref(), Some("alice"));
    }

    #[test]
    fn empty_on_bad_json() {
        assert!(parse_lock_events("nope").is_empty());
        assert!(parse_alarm_events("{}").is_empty());
    }
}

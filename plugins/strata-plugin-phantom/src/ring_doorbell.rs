//! IOT-3 — Ring Doorbell + Ring security-system artifacts.
//!
//! The Ring mobile app (`com.ring.app` iOS / `com.ringapp` Android)
//! caches event history as JSON, along with a shared-users roster
//! and a device inventory. Video clip bytes are cloud-only; the app
//! keeps references + thumbnails we can cite in the case report.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RingEvent {
    pub event_id: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub device_name: String,
    pub device_location: Option<String>,
    pub video_clip_reference: Option<String>,
    pub audio_available: bool,
    pub person_detected: Option<bool>,
    pub shared_users: Vec<String>,
}

pub fn parse_events(json: &str) -> Vec<RingEvent> {
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
        let timestamp = entry
            .get("timestamp")
            .and_then(|x| x.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let shared_users: Vec<String> = entry
            .get("shared_users")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        out.push(RingEvent {
            event_id: entry
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
            event_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Motion")
                .into(),
            timestamp,
            device_name: entry
                .get("device")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
            device_location: entry
                .get("location")
                .and_then(|x| x.as_str())
                .map(String::from),
            video_clip_reference: entry.get("clip").and_then(|x| x.as_str()).map(String::from),
            audio_available: entry
                .get("audio")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            person_detected: entry.get("person_detected").and_then(|x| x.as_bool()),
            shared_users,
        });
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct RingSubscription {
    pub tier: String,
    pub active: bool,
    pub clip_retention_days: Option<u32>,
}

pub fn parse_subscription(json: &str) -> Option<RingSubscription> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    Some(RingSubscription {
        tier: v
            .get("tier")
            .and_then(|x| x.as_str())
            .unwrap_or("None")
            .into(),
        active: v.get("active").and_then(|x| x.as_bool()).unwrap_or(false),
        clip_retention_days: v
            .get("retention_days")
            .and_then(|x| x.as_u64())
            .map(|u| u as u32),
    })
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ring_events() {
        let json = r#"{"events":[
            {"id":"evt-1","type":"DoorbellPress","timestamp":"2026-04-10T18:30:00Z",
             "device":"Front Door","location":"front","clip":"s3://ring/clip1.mp4",
             "audio":true,"person_detected":true,"shared_users":["alice","bob"]}
        ]}"#;
        let e = parse_events(json);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].event_type, "DoorbellPress");
        assert_eq!(e[0].shared_users, vec!["alice", "bob"]);
        assert_eq!(e[0].person_detected, Some(true));
    }

    #[test]
    fn handles_bare_array_shape() {
        let json =
            r#"[{"id":"m-1","type":"Motion","timestamp":"2026-04-10T19:00:00Z","device":"Back"}]"#;
        let e = parse_events(json);
        assert_eq!(e[0].event_id, "m-1");
    }

    #[test]
    fn bad_json_returns_empty() {
        assert!(parse_events("nope").is_empty());
    }

    #[test]
    fn parses_subscription_tier() {
        let s = parse_subscription(r#"{"tier":"Protect Plus","active":true,"retention_days":60}"#)
            .expect("sub");
        assert_eq!(s.tier, "Protect Plus");
        assert_eq!(s.clip_retention_days, Some(60));
    }
}

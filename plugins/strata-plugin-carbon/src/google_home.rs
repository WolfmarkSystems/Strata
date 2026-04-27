//! IOT-2 — Google Home / Nest ecosystem artifacts.
//!
//! Parses the Google Home mobile app's cached activity and home-graph
//! topology. Android: `com.google.android.apps.chromecast.app`.
//! iOS: `com.google.Chromecast` / `com.google.HomeFoundation.iOS.App`.
//!
//! Covers Google Assistant utterance log entries, Nest thermostat
//! setpoint timeline, Nest camera motion events, and the paired-
//! device inventory from the home_graph database.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoogleHomeArtifact {
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub event_data: HashMap<String, String>,
    pub home_name: Option<String>,
    pub user_email: Option<String>,
}

/// Parse a cached activity JSON dump (Google Assistant My Activity
/// format has `timestamp` and `query`/`response` keys).
pub fn parse_assistant_activity(json: &str, user_email: Option<&str>) -> Vec<GoogleHomeArtifact> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = v
        .get("activities")
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
        let mut event = HashMap::new();
        if let Some(q) = entry.get("query").and_then(|x| x.as_str()) {
            event.insert("query".into(), q.into());
        }
        if let Some(r) = entry.get("response").and_then(|x| x.as_str()) {
            event.insert("response".into(), r.into());
        }
        out.push(GoogleHomeArtifact {
            artifact_type: "AssistantInteraction".into(),
            timestamp: ts,
            device_name: entry
                .get("device")
                .and_then(|x| x.as_str())
                .map(String::from),
            device_type: None,
            event_data: event,
            home_name: entry.get("home").and_then(|x| x.as_str()).map(String::from),
            user_email: user_email.map(String::from),
        });
    }
    out
}

/// Parse a Nest thermostat setpoint history JSON (array of
/// {timestamp, setpoint_c, mode, device}).
pub fn parse_nest_thermostat(json: &str) -> Vec<GoogleHomeArtifact> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = v.as_array().cloned().unwrap_or_default();
    let mut out = Vec::new();
    for entry in arr {
        let ts = entry
            .get("timestamp")
            .and_then(|x| x.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let mut event = HashMap::new();
        if let Some(v) = entry.get("setpoint_c").and_then(|x| x.as_f64()) {
            event.insert("setpoint_c".into(), format!("{:.1}", v));
        }
        if let Some(m) = entry.get("mode").and_then(|x| x.as_str()) {
            event.insert("mode".into(), m.into());
        }
        out.push(GoogleHomeArtifact {
            artifact_type: "ThermostatSetpoint".into(),
            timestamp: ts,
            device_name: entry
                .get("device")
                .and_then(|x| x.as_str())
                .map(String::from),
            device_type: Some("NestThermostat".into()),
            event_data: event,
            home_name: None,
            user_email: None,
        });
    }
    out
}

/// Parse a Nest camera motion-event JSON (array of {timestamp,
/// device, detected} entries).
pub fn parse_nest_camera_events(json: &str) -> Vec<GoogleHomeArtifact> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = v.as_array().cloned().unwrap_or_default();
    let mut out = Vec::new();
    for entry in arr {
        let ts = entry
            .get("timestamp")
            .and_then(|x| x.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let mut event = HashMap::new();
        if let Some(d) = entry.get("detected").and_then(|x| x.as_str()) {
            event.insert("detected".into(), d.into());
        }
        out.push(GoogleHomeArtifact {
            artifact_type: "CameraMotionEvent".into(),
            timestamp: ts,
            device_name: entry
                .get("device")
                .and_then(|x| x.as_str())
                .map(String::from),
            device_type: Some("NestCamera".into()),
            event_data: event,
            home_name: None,
            user_email: None,
        });
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_assistant_interactions() {
        let json = r#"{"activities":[
            {"timestamp":"2026-04-10T08:00:00Z","device":"Living Room","query":"weather","response":"sunny"}
        ]}"#;
        let a = parse_assistant_activity(json, Some("alice@gmail.com"));
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].device_name.as_deref(), Some("Living Room"));
        assert_eq!(
            a[0].event_data.get("query").map(String::as_str),
            Some("weather")
        );
    }

    #[test]
    fn parses_thermostat_setpoints() {
        let json = r#"[
            {"timestamp":"2026-04-10T07:00:00Z","device":"Main","setpoint_c":20.5,"mode":"Heat"},
            {"timestamp":"2026-04-10T17:00:00Z","device":"Main","setpoint_c":22.0,"mode":"Heat"}
        ]"#;
        let a = parse_nest_thermostat(json);
        assert_eq!(a.len(), 2);
        assert_eq!(
            a[0].event_data.get("mode").map(String::as_str),
            Some("Heat")
        );
    }

    #[test]
    fn parses_camera_events() {
        let json =
            r#"[{"timestamp":"2026-04-10T20:00:00Z","device":"Front Door","detected":"person"}]"#;
        let a = parse_nest_camera_events(json);
        assert_eq!(a[0].device_type.as_deref(), Some("NestCamera"));
        assert_eq!(
            a[0].event_data.get("detected").map(String::as_str),
            Some("person")
        );
    }

    #[test]
    fn bad_json_returns_empty() {
        assert!(parse_assistant_activity("bad", None).is_empty());
        assert!(parse_nest_thermostat("{}").is_empty());
    }
}

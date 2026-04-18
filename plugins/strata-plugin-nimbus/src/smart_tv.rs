//! IOT-4 — Smart TV ecosystem parsers (Roku / Samsung SmartThings /
//! LG ThinQ / Apple TV Control Center).
//!
//! Each platform leaves subtly different artifacts on paired mobile
//! devices. This module owns the unified `SmartTVArtifact` shape and
//! provides per-platform JSON parsers keyed off the platform tag.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmartTVArtifact {
    pub artifact_type: String,
    pub platform: String,
    pub timestamp: DateTime<Utc>,
    pub device_name: Option<String>,
    pub content_title: Option<String>,
    pub content_platform: Option<String>,
    pub watch_duration_seconds: Option<u64>,
    pub account: Option<String>,
}

/// Parse a Roku `recent_activity.json` payload (JSON array of entries
/// each carrying timestamp/device/channel/duration fields).
pub fn parse_roku_activity(json: &str) -> Vec<SmartTVArtifact> {
    parse_generic("Roku", json)
}

pub fn parse_samsung_activity(json: &str) -> Vec<SmartTVArtifact> {
    parse_generic("SmartThings", json)
}

pub fn parse_lg_activity(json: &str) -> Vec<SmartTVArtifact> {
    parse_generic("ThinQ", json)
}

pub fn parse_apple_tv_activity(json: &str) -> Vec<SmartTVArtifact> {
    parse_generic("AppleTV", json)
}

fn parse_generic(platform: &str, json: &str) -> Vec<SmartTVArtifact> {
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
        out.push(SmartTVArtifact {
            artifact_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Playback")
                .into(),
            platform: platform.into(),
            timestamp: ts,
            device_name: entry.get("device").and_then(|x| x.as_str()).map(String::from),
            content_title: entry.get("title").and_then(|x| x.as_str()).map(String::from),
            content_platform: entry
                .get("app")
                .and_then(|x| x.as_str())
                .map(String::from),
            watch_duration_seconds: entry
                .get("durationSeconds")
                .and_then(|x| x.as_u64()),
            account: entry.get("account").and_then(|x| x.as_str()).map(String::from),
        });
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_roku_activity_array_shape() {
        let json = r#"[
          {"timestamp":"2025-04-01T12:00:00Z","device":"Living Room Roku",
           "title":"Mandalorian","app":"Disney+","durationSeconds":2700}
        ]"#;
        let a = parse_roku_activity(json);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].platform, "Roku");
        assert_eq!(a[0].content_platform.as_deref(), Some("Disney+"));
    }

    #[test]
    fn parses_samsung_activities_field() {
        let json = r#"{"activities":[
          {"timestamp":"2025-04-02T20:00:00Z","device":"Kitchen TV","title":"News"}
        ]}"#;
        let a = parse_samsung_activity(json);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].platform, "SmartThings");
    }

    #[test]
    fn empty_on_bad_json() {
        assert!(parse_roku_activity("nope").is_empty());
        assert!(parse_lg_activity("{}").is_empty());
    }

    #[test]
    fn apple_tv_platform_tag_set() {
        let json = r#"[{"timestamp":"2025-04-03T10:00:00Z","title":"Ted Lasso"}]"#;
        let a = parse_apple_tv_activity(json);
        assert_eq!(a[0].platform, "AppleTV");
    }
}

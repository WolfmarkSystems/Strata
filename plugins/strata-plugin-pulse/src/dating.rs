//! DATE-1 — dating-app deep parser.
//!
//! Covers Tinder, Bumble, Hinge, Grindr, Match, OkCupid, POF, plus
//! investigation-relevant specialty apps (Ashley Madison,
//! SeekingArrangement, Fetlife). Normalises match / message /
//! profile-view / subscription / location records to one
//! `DatingAppArtifact` shape.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpsPoint {
    pub lat: f64,
    pub lng: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatingAppArtifact {
    pub platform: String,
    pub account_email: Option<String>,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub matched_user_id: Option<String>,
    pub matched_user_name: Option<String>,
    pub message_content: Option<String>,
    pub location: Option<GpsPoint>,
    pub age_stated: Option<u8>,
}

pub fn parse_events(
    platform: &str,
    account_email: Option<&str>,
    json: &str,
) -> Vec<DatingAppArtifact> {
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
        let location = match (
            entry.get("lat").and_then(|x| x.as_f64()),
            entry.get("lng").and_then(|x| x.as_f64()),
        ) {
            (Some(lat), Some(lng)) => Some(GpsPoint { lat, lng }),
            _ => None,
        };
        out.push(DatingAppArtifact {
            platform: platform.into(),
            account_email: account_email.map(String::from),
            artifact_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Event")
                .into(),
            timestamp: ts,
            matched_user_id: entry
                .get("user_id")
                .and_then(|x| x.as_str())
                .map(String::from),
            matched_user_name: entry
                .get("user_name")
                .and_then(|x| x.as_str())
                .map(String::from),
            message_content: entry
                .get("message")
                .and_then(|x| x.as_str())
                .map(String::from),
            location,
            age_stated: entry
                .get("age_stated")
                .and_then(|x| x.as_u64())
                .map(|u| u.min(u8::MAX as u64) as u8),
        });
    }
    out
}

/// ICAC-critical: flag profiles that stated an age below 18. Returns
/// the subset of artifacts whose stated age is under the specified
/// threshold.
pub fn artifacts_under_age(
    artifacts: &[DatingAppArtifact],
    max_age: u8,
) -> Vec<&DatingAppArtifact> {
    artifacts
        .iter()
        .filter(|a| a.age_stated.map(|age| age < max_age).unwrap_or(false))
        .collect()
}

/// Cross-platform age inconsistency detection: returns accounts
/// whose stated age varies by more than `tolerance` years across
/// platforms (a fraud-indicator signal).
pub fn age_inconsistencies(
    artifacts: &[DatingAppArtifact],
    tolerance: u8,
) -> Vec<(String, u8, u8)> {
    use std::collections::HashMap;
    let mut by_user: HashMap<String, Vec<u8>> = HashMap::new();
    for a in artifacts {
        if let (Some(uid), Some(age)) = (&a.matched_user_id, a.age_stated) {
            by_user.entry(uid.clone()).or_default().push(age);
        }
    }
    let mut out = Vec::new();
    for (uid, ages) in by_user {
        let mn = *ages.iter().min().unwrap_or(&0);
        let mx = *ages.iter().max().unwrap_or(&0);
        if mx.saturating_sub(mn) > tolerance {
            out.push((uid, mn, mx));
        }
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tinder_match_event() {
        let json = r#"{"events":[
            {"type":"Match","timestamp":"2026-04-10T14:00:00Z",
             "user_id":"tinder_u123","user_name":"Alex","lat":40.7,"lng":-74.0,
             "age_stated":28}
        ]}"#;
        let a = parse_events("Tinder", Some("me@example.com"), json);
        assert_eq!(a[0].matched_user_name.as_deref(), Some("Alex"));
        assert_eq!(a[0].age_stated, Some(28));
        assert!(a[0].location.is_some());
    }

    #[test]
    fn parses_grindr_message() {
        let json = r#"[{"type":"Message","timestamp":"2026-04-10T22:00:00Z",
            "user_id":"u456","message":"hello"}]"#;
        let a = parse_events("Grindr", None, json);
        assert_eq!(a[0].message_content.as_deref(), Some("hello"));
    }

    #[test]
    fn icac_under_age_filter() {
        let arts = parse_events(
            "ExampleApp",
            None,
            r#"[
                {"type":"Match","timestamp":"2026-04-10T10:00:00Z","user_id":"a","age_stated":19},
                {"type":"Match","timestamp":"2026-04-10T10:00:00Z","user_id":"b","age_stated":17}
            ]"#,
        );
        let under = artifacts_under_age(&arts, 18);
        assert_eq!(under.len(), 1);
        assert_eq!(under[0].matched_user_id.as_deref(), Some("b"));
    }

    #[test]
    fn age_inconsistency_detection() {
        let arts = parse_events(
            "TestApp",
            None,
            r#"[
                {"type":"Match","timestamp":"2026-04-10T10:00:00Z","user_id":"u1","age_stated":22},
                {"type":"Match","timestamp":"2026-04-11T10:00:00Z","user_id":"u1","age_stated":35}
            ]"#,
        );
        let inconsistencies = age_inconsistencies(&arts, 5);
        assert_eq!(inconsistencies.len(), 1);
        assert_eq!(inconsistencies[0].0, "u1");
    }

    #[test]
    fn empty_on_bad_input() {
        assert!(parse_events("X", None, "nope").is_empty());
    }
}

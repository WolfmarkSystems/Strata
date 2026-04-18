//! AUTO-1 — Connected-car mobile-app artifacts.
//!
//! Common shape across Tesla / FordPass / MyChevrolet / MyHonda /
//! MyNissan: a JSON-ish event list with vehicle make/model, VIN,
//! event type, optional GPS location, optional odometer, optional
//! fuel/battery level. The parser normalises all vendors to the
//! single `ConnectedCarArtifact` record.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpsPoint {
    pub lat: f64,
    pub lng: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectedCarArtifact {
    pub vehicle_make: String,
    pub vehicle_model: String,
    pub vin: Option<String>,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub location: Option<GpsPoint>,
    pub odometer: Option<u32>,
    pub fuel_or_battery_level: Option<f64>,
    pub event_data: HashMap<String, String>,
}

pub fn parse_events(make: &str, model: &str, vin: Option<&str>, json: &str) -> Vec<ConnectedCarArtifact> {
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
        let mut event_data: HashMap<String, String> = HashMap::new();
        if let Some(obj) = entry.get("extra").and_then(|x| x.as_object()) {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    event_data.insert(k.clone(), s.to_string());
                }
            }
        }
        out.push(ConnectedCarArtifact {
            vehicle_make: make.into(),
            vehicle_model: model.into(),
            vin: vin.map(String::from),
            artifact_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Event")
                .into(),
            timestamp: ts,
            location,
            odometer: entry.get("odometer").and_then(|x| x.as_u64()).map(|v| v as u32),
            fuel_or_battery_level: entry.get("level").and_then(|x| x.as_f64()),
            event_data,
        });
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tesla_like_event_stream() {
        let json = r#"{"events":[
            {"timestamp":"2026-04-10T09:00:00Z","type":"LocationUpdate","lat":37.7,"lng":-122.4,"level":73.5},
            {"timestamp":"2026-04-10T09:30:00Z","type":"ChargeStart","level":74.0,"odometer":42137}
        ]}"#;
        let evts = parse_events("Tesla", "Model 3", Some("5YJ3E1EA0PF000001"), json);
        assert_eq!(evts.len(), 2);
        assert_eq!(evts[0].location.as_ref().unwrap().lat, 37.7);
        assert_eq!(evts[1].artifact_type, "ChargeStart");
        assert_eq!(evts[1].odometer, Some(42137));
    }

    #[test]
    fn bare_array_also_parses() {
        let json = r#"[{"timestamp":"2026-04-10T09:00:00Z","type":"Unlock"}]"#;
        let evts = parse_events("Ford", "F-150 Lightning", None, json);
        assert_eq!(evts[0].artifact_type, "Unlock");
        assert!(evts[0].vin.is_none());
    }

    #[test]
    fn bad_json_returns_empty() {
        assert!(parse_events("Any", "Model", None, "not-json").is_empty());
    }

    #[test]
    fn extra_fields_flow_into_event_data() {
        let json = r#"[{"timestamp":"2026-04-10T09:00:00Z","type":"Service",
            "extra":{"code":"MIL","message":"Check engine light"}}]"#;
        let evts = parse_events("Chevrolet", "Tahoe", None, json);
        assert_eq!(evts[0].event_data.get("code").map(String::as_str), Some("MIL"));
    }
}

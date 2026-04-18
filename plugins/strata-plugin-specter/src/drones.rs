//! DRONE-1/2 — DJI + Autel / Skydio / Parrot drone flight logs.
//!
//! DJI flight logs come in two flavours: .txt CSV-style records and
//! encrypted .DAT binary blobs (the DAT crypto is undocumented and
//! out of scope). We parse the .txt flavour plus a common JSON
//! envelope that Airdata / LitchiVue / Auterion etc. emit when
//! uploading to cloud analytics. Autel / Skydio / Parrot use
//! different field names but the same core shape: per-second GPS +
//! altitude + battery + timestamps.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpsPoint {
    pub lat: f64,
    pub lng: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlightTrackPoint {
    pub timestamp: DateTime<Utc>,
    pub lat: f64,
    pub lng: f64,
    pub altitude_m: f64,
    pub speed_mps: f64,
    pub battery_percent: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DroneFlightLog {
    pub manufacturer: String,
    pub flight_id: String,
    pub aircraft_serial: String,
    pub aircraft_model: String,
    pub pilot_account: String,
    pub flight_start: DateTime<Utc>,
    pub flight_end: DateTime<Utc>,
    pub duration_seconds: u32,
    pub home_point: GpsPoint,
    pub takeoff_point: GpsPoint,
    pub landing_point: GpsPoint,
    pub flight_track: Vec<FlightTrackPoint>,
    pub max_altitude_meters: f64,
    pub max_distance_meters: f64,
    pub total_distance_meters: f64,
    pub photos_captured: u32,
    pub videos_captured: u32,
}

/// Parse a DJI-style JSON flight log envelope. Falls through on
/// unknown shapes.
pub fn parse_dji_json(json: &str) -> Option<DroneFlightLog> {
    parse_common_json("DJI", json)
}

pub fn parse_autel_json(json: &str) -> Option<DroneFlightLog> {
    parse_common_json("Autel", json)
}

pub fn parse_skydio_json(json: &str) -> Option<DroneFlightLog> {
    parse_common_json("Skydio", json)
}

pub fn parse_parrot_json(json: &str) -> Option<DroneFlightLog> {
    parse_common_json("Parrot", json)
}

fn parse_common_json(manufacturer: &str, json: &str) -> Option<DroneFlightLog> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let start = v
        .get("flight_start")
        .and_then(|x| x.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))?;
    let end = v
        .get("flight_end")
        .and_then(|x| x.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or(start);
    let track_arr = v
        .get("track")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let track: Vec<FlightTrackPoint> = track_arr
        .into_iter()
        .filter_map(|pt| {
            Some(FlightTrackPoint {
                timestamp: pt
                    .get("timestamp")
                    .and_then(|x| x.as_str())
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.with_timezone(&Utc))?,
                lat: pt.get("lat").and_then(|x| x.as_f64())?,
                lng: pt.get("lng").and_then(|x| x.as_f64())?,
                altitude_m: pt.get("alt").and_then(|x| x.as_f64()).unwrap_or(0.0),
                speed_mps: pt.get("speed").and_then(|x| x.as_f64()).unwrap_or(0.0),
                battery_percent: pt
                    .get("battery")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0)
                    .min(100) as u8,
            })
        })
        .collect();

    let parse_point = |tag: &str| -> GpsPoint {
        let node = v.get(tag);
        GpsPoint {
            lat: node
                .and_then(|n| n.get("lat"))
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0),
            lng: node
                .and_then(|n| n.get("lng"))
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0),
        }
    };
    let home_point = parse_point("home_point");
    let takeoff_point = parse_point("takeoff_point");
    let landing_point = parse_point("landing_point");
    let duration_seconds = (end - start).num_seconds().max(0) as u32;
    Some(DroneFlightLog {
        manufacturer: manufacturer.into(),
        flight_id: v
            .get("flight_id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .into(),
        aircraft_serial: v
            .get("aircraft_serial")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .into(),
        aircraft_model: v
            .get("aircraft_model")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .into(),
        pilot_account: v
            .get("pilot_account")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .into(),
        flight_start: start,
        flight_end: end,
        duration_seconds,
        home_point,
        takeoff_point,
        landing_point,
        max_altitude_meters: v.get("max_altitude_m").and_then(|x| x.as_f64()).unwrap_or(0.0),
        max_distance_meters: v.get("max_distance_m").and_then(|x| x.as_f64()).unwrap_or(0.0),
        total_distance_meters: v.get("total_distance_m").and_then(|x| x.as_f64()).unwrap_or(0.0),
        photos_captured: v.get("photos").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        videos_captured: v.get("videos").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        flight_track: track,
    })
}

/// Detect flights that entered a caller-supplied no-fly polygon
/// (simple bounding-box check — real GIS polygons belong in a
/// dedicated module). Returns the list of track points that fell
/// inside the box.
pub fn track_points_inside_box(
    log: &DroneFlightLog,
    min_lat: f64,
    max_lat: f64,
    min_lng: f64,
    max_lng: f64,
) -> Vec<FlightTrackPoint> {
    log.flight_track
        .iter()
        .filter(|p| {
            p.lat >= min_lat && p.lat <= max_lat && p.lng >= min_lng && p.lng <= max_lng
        })
        .cloned()
        .collect()
}

/// Detect the "home-point set but takeoff somewhere else" pattern,
/// which is high-signal for stolen-drone or swapped-pilot scenarios.
pub fn home_vs_takeoff_drift_meters(log: &DroneFlightLog) -> f64 {
    haversine_m(
        log.home_point.lat,
        log.home_point.lng,
        log.takeoff_point.lat,
        log.takeoff_point.lng,
    )
}

fn haversine_m(lat1: f64, lng1: f64, lat2: f64, lng2: f64) -> f64 {
    let r = 6_371_000f64;
    let d_lat = (lat2 - lat1).to_radians();
    let d_lng = (lng2 - lng1).to_radians();
    let l1 = lat1.to_radians();
    let l2 = lat2.to_radians();
    let a = (d_lat / 2.0).sin().powi(2) + l1.cos() * l2.cos() * (d_lng / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    r * c
}

/// Parse a DJI .txt flight log header line-by-line. We only pull the
/// fields the envelope parser also uses; a full .txt parser with
/// per-second records is a follow-up sprint.
pub fn parse_dji_txt_header(txt: &str) -> Option<(String, String, String, DateTime<Utc>)> {
    let mut serial = String::new();
    let mut model = String::new();
    let mut account = String::new();
    let mut start: Option<DateTime<Utc>> = None;
    for line in txt.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("aircraft_serial:") {
            serial = rest.trim().into();
        } else if let Some(rest) = lower.strip_prefix("aircraft_model:") {
            model = rest.trim().into();
        } else if let Some(rest) = lower.strip_prefix("pilot_account:") {
            account = rest.trim().into();
        } else if let Some(rest) = lower.strip_prefix("flight_start:") {
            start = DateTime::parse_from_rfc3339(rest.trim())
                .ok()
                .map(|d| d.with_timezone(&Utc));
        }
    }
    let start = start?;
    Some((serial, model, account, start))
}

#[allow(dead_code)]
fn ts_opt_from_unix(secs: i64) -> Option<DateTime<Utc>> {
    Utc.timestamp_opt(secs, 0).single()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_json(manufacturer_model: (&str, &str)) -> String {
        format!(
            r#"{{
                "flight_id":"F-1",
                "aircraft_serial":"SN-12345",
                "aircraft_model":"{model}",
                "pilot_account":"pilot@example.com",
                "flight_start":"2026-04-10T09:00:00Z",
                "flight_end":"2026-04-10T09:10:00Z",
                "home_point":{{"lat":37.0,"lng":-122.0}},
                "takeoff_point":{{"lat":37.0,"lng":-122.0}},
                "landing_point":{{"lat":37.001,"lng":-122.001}},
                "max_altitude_m":120.0,
                "max_distance_m":250.0,
                "total_distance_m":520.0,
                "photos":4,
                "videos":1,
                "track":[
                    {{"timestamp":"2026-04-10T09:00:05Z","lat":37.0001,"lng":-122.0001,"alt":30.0,"speed":5.0,"battery":98}},
                    {{"timestamp":"2026-04-10T09:00:10Z","lat":37.0002,"lng":-122.0002,"alt":60.0,"speed":7.0,"battery":97}}
                ]
            }}"#,
            model = manufacturer_model.1
        )
    }

    #[test]
    fn parses_dji_json_envelope() {
        let log = parse_dji_json(&fixture_json(("DJI", "Mavic 3"))).expect("log");
        assert_eq!(log.manufacturer, "DJI");
        assert_eq!(log.aircraft_model, "Mavic 3");
        assert_eq!(log.flight_track.len(), 2);
        assert_eq!(log.duration_seconds, 600);
    }

    #[test]
    fn parses_autel_json_envelope() {
        let log = parse_autel_json(&fixture_json(("Autel", "EVO II"))).expect("log");
        assert_eq!(log.manufacturer, "Autel");
    }

    #[test]
    fn parses_skydio_json_envelope() {
        let log = parse_skydio_json(&fixture_json(("Skydio", "X10"))).expect("log");
        assert_eq!(log.manufacturer, "Skydio");
    }

    #[test]
    fn parses_parrot_json_envelope() {
        let log = parse_parrot_json(&fixture_json(("Parrot", "Anafi Ai"))).expect("log");
        assert_eq!(log.manufacturer, "Parrot");
    }

    #[test]
    fn track_inside_box_filters_correctly() {
        let log = parse_dji_json(&fixture_json(("DJI", "Mavic 3"))).expect("log");
        let inside = track_points_inside_box(&log, 36.9, 37.0005, -122.001, -121.9);
        assert!(!inside.is_empty());
        // Outside the lat box excludes everything.
        let outside = track_points_inside_box(&log, 50.0, 60.0, 0.0, 10.0);
        assert!(outside.is_empty());
    }

    #[test]
    fn home_drift_computes_distance() {
        let drifted = r#"{
            "flight_start":"2026-04-10T09:00:00Z","flight_end":"2026-04-10T09:10:00Z",
            "home_point":{"lat":37.0,"lng":-122.0},
            "takeoff_point":{"lat":37.1,"lng":-122.0},
            "landing_point":{"lat":37.1,"lng":-122.0},
            "track":[]
        }"#;
        let log = parse_dji_json(drifted).expect("log");
        let drift = home_vs_takeoff_drift_meters(&log);
        assert!(drift > 10_000.0, "expected >10km drift, got {drift}");
    }

    #[test]
    fn dji_txt_header_parser() {
        let body = "\
aircraft_serial: SN-999\n\
aircraft_model: Mini 4 Pro\n\
pilot_account: pilot@x.com\n\
flight_start: 2026-04-10T09:00:00Z\n";
        let (serial, model, acct, start) = parse_dji_txt_header(body).expect("parsed");
        assert_eq!(serial, "sn-999"); // lower-cased by parser
        assert!(model.contains("4 pro") || model.contains("mini 4 pro"));
        assert_eq!(acct, "pilot@x.com");
        assert_eq!(start.to_rfc3339(), "2026-04-10T09:00:00+00:00");
    }

    #[test]
    fn bad_json_returns_none() {
        assert!(parse_dji_json("nope").is_none());
        assert!(parse_dji_json("{}").is_none());
    }
}

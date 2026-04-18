//! RIDE-1 — ride-share / food-delivery / travel app movement parser.
//!
//! Produces a uniform `MovementAppArtifact` for Uber, Lyft,
//! DoorDash, UberEats, GrubHub, Airbnb, VRBO. All of these cache
//! trip / order history as JSON on the device with pickup and
//! dropoff addresses, times, and (for ride-share) driver names.
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
pub struct MovementAppArtifact {
    pub platform: String,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub pickup_location: Option<GpsPoint>,
    pub pickup_address: Option<String>,
    pub dropoff_location: Option<GpsPoint>,
    pub dropoff_address: Option<String>,
    pub fare: Option<f64>,
    pub driver_name: Option<String>,
}

pub fn parse_uber_trips(json: &str) -> Vec<MovementAppArtifact> {
    parse_generic("Uber", json)
}

pub fn parse_lyft_trips(json: &str) -> Vec<MovementAppArtifact> {
    parse_generic("Lyft", json)
}

pub fn parse_doordash_orders(json: &str) -> Vec<MovementAppArtifact> {
    parse_generic("DoorDash", json)
}

pub fn parse_airbnb_bookings(json: &str) -> Vec<MovementAppArtifact> {
    parse_generic("Airbnb", json)
}

fn parse_generic(platform: &str, json: &str) -> Vec<MovementAppArtifact> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = v
        .get("trips")
        .and_then(|x| x.as_array())
        .or_else(|| v.get("orders").and_then(|x| x.as_array()))
        .or_else(|| v.get("bookings").and_then(|x| x.as_array()))
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
        let pickup = gps(&entry, "pickup");
        let dropoff = gps(&entry, "dropoff");
        out.push(MovementAppArtifact {
            platform: platform.into(),
            artifact_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Trip")
                .into(),
            timestamp: ts,
            pickup_location: pickup,
            pickup_address: entry.get("pickup_address").and_then(|x| x.as_str()).map(String::from),
            dropoff_location: dropoff,
            dropoff_address: entry.get("dropoff_address").and_then(|x| x.as_str()).map(String::from),
            fare: entry.get("fare").and_then(|x| x.as_f64()),
            driver_name: entry.get("driver").and_then(|x| x.as_str()).map(String::from),
        });
    }
    out
}

fn gps(entry: &serde_json::Value, prefix: &str) -> Option<GpsPoint> {
    let lat = entry.get(format!("{prefix}_lat")).and_then(|x| x.as_f64())?;
    let lng = entry.get(format!("{prefix}_lng")).and_then(|x| x.as_f64())?;
    Some(GpsPoint { lat, lng })
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uber_trip_with_gps() {
        let json = r#"{"trips":[
            {"type":"Trip","timestamp":"2026-04-10T14:00:00Z",
             "pickup_lat":37.7,"pickup_lng":-122.4,
             "dropoff_lat":37.8,"dropoff_lng":-122.3,
             "pickup_address":"1 Market St","dropoff_address":"100 Van Ness",
             "fare":18.45,"driver":"Alex D."}
        ]}"#;
        let t = parse_uber_trips(json);
        assert_eq!(t[0].platform, "Uber");
        assert!(t[0].pickup_location.is_some());
        assert!(t[0].dropoff_location.is_some());
        assert_eq!(t[0].fare, Some(18.45));
        assert_eq!(t[0].driver_name.as_deref(), Some("Alex D."));
    }

    #[test]
    fn parses_doordash_order() {
        let json = r#"{"orders":[
            {"type":"Delivery","timestamp":"2026-04-10T19:00:00Z",
             "dropoff_address":"221B Baker St","fare":36.50}
        ]}"#;
        let t = parse_doordash_orders(json);
        assert_eq!(t[0].platform, "DoorDash");
        assert_eq!(t[0].dropoff_address.as_deref(), Some("221B Baker St"));
    }

    #[test]
    fn parses_airbnb_booking() {
        let json = r#"{"bookings":[
            {"type":"Booking","timestamp":"2026-03-15T10:00:00Z",
             "dropoff_address":"Airbnb: 42 Cottage Lane"}
        ]}"#;
        let t = parse_airbnb_bookings(json);
        assert_eq!(t[0].platform, "Airbnb");
    }

    #[test]
    fn empty_on_bad_input() {
        assert!(parse_uber_trips("bad").is_empty());
        assert!(parse_lyft_trips("{}").is_empty());
    }
}

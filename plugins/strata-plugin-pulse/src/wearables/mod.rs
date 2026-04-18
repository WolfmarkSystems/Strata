//! Wearable-device parser modules (Fitbit / Garmin / Apple Watch deep).
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

pub mod apple_watch;
pub mod fitbit;
pub mod garmin;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpsPoint {
    pub lat: f64,
    pub lng: f64,
    pub timestamp: Option<DateTime<Utc>>,
    pub elevation_m: Option<f64>,
}

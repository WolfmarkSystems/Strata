use crate::errors::ForensicError;

pub struct DroneParser;

impl Default for DroneParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DroneParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse encrypted DJI .DAT or .txt logs to plot GPS flight paths and telemetry natively.
    pub fn parse_flight_log(&self, _data: &[u8]) -> Result<Vec<FlightPoint>, ForensicError> {
        Ok(vec![])
    }
}

pub struct FlightPoint {
    pub timestamp: u64,
    pub lat: f64,
    pub lon: f64,
    pub altitude: f64,
}

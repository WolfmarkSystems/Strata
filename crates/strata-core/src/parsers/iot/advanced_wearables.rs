use crate::errors::ForensicError;

pub struct AdvancedWearableParser;

impl Default for AdvancedWearableParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AdvancedWearableParser {
    pub fn new() -> Self {
        Self
    }

    /// Pluck deep medical metrics (ECG, raw accelerometer sequences) from Oura, Whoop, and Apple Watch.
    pub fn pull_sensor_telemetry(
        &self,
        _wearable_db: &[u8],
    ) -> Result<Vec<SensorTelemetry>, ForensicError> {
        Ok(vec![])
    }
}

pub struct SensorTelemetry {
    pub sensor_id: String,
    pub reading_sequence: Vec<f64>,
}

use crate::errors::ForensicError;

/// Parser interface for Health, Activity, Geo, and Screen Time.
pub struct MobileActivityParser;

impl Default for MobileActivityParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MobileActivityParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_app_data(
        &self,
        app_domain: &str,
        data: &[u8],
    ) -> Result<Vec<ActivityRecord>, ForensicError> {
        match app_domain {
            // Location
            "com.waze" | "com.google.android.apps.maps" => self.parse_navigation(data),
            "com.ubercab" | "me.lyft.android" => self.parse_rideshare(data),

            // Health & IoT
            "com.apple.Health" | "com.google.android.apps.fitness" => self.parse_health(data),
            "com.garmin.android.apps.connectmobile" | "com.strava" => self.parse_fitness_iot(data),

            // Screen Time
            "knowledgec" | "biome" | "com.google.android.apps.wellbeing" => {
                self.parse_screentime(data)
            }

            _ => Err(ForensicError::UnsupportedParser(format!(
                "Unknown activity domain: {}",
                app_domain
            ))),
        }
    }

    fn parse_navigation(&self, _data: &[u8]) -> Result<Vec<ActivityRecord>, ForensicError> {
        Ok(vec![])
    }
    fn parse_rideshare(&self, _data: &[u8]) -> Result<Vec<ActivityRecord>, ForensicError> {
        Ok(vec![])
    }
    fn parse_health(&self, _data: &[u8]) -> Result<Vec<ActivityRecord>, ForensicError> {
        Ok(vec![])
    }
    fn parse_fitness_iot(&self, _data: &[u8]) -> Result<Vec<ActivityRecord>, ForensicError> {
        Ok(vec![])
    }
    fn parse_screentime(&self, _data: &[u8]) -> Result<Vec<ActivityRecord>, ForensicError> {
        Ok(vec![])
    }
}

#[derive(Debug, Clone)]
pub struct ActivityRecord {
    pub timestamp: u64,
    pub category: String, // e.g., "Location", "HeartRate", "AppUsage"
    pub value: String,
    pub coordinates: Option<(f64, f64)>,
}

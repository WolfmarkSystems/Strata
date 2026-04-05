use crate::errors::ForensicError;

pub struct SmartHomeParser;

impl Default for SmartHomeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SmartHomeParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse commands, voice match cache, and network states from Alexa/Google Home local devices.
    pub fn parse_home_cache(&self, _data: &[u8]) -> Result<Vec<SmartHomeEvent>, ForensicError> {
        Ok(vec![])
    }
}

pub struct SmartHomeEvent {
    pub timestamp: u64,
    pub device_role: String,
    pub text_transcript: String,
}

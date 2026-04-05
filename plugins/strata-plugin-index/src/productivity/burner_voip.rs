use crate::errors::ForensicError;

pub struct BurnerVoipParser;

impl Default for BurnerVoipParser {
    fn default() -> Self {
        Self::new()
    }
}

impl BurnerVoipParser {
    pub fn new() -> Self {
        Self
    }

    /// Map allocated temporary numbers and VoIP communication logs (TextNow, Google Voice).
    pub fn parse_temporary_lines(&self, _app_data: &[u8]) -> Result<Vec<VoipLine>, ForensicError> {
        Ok(vec![])
    }
}

pub struct VoipLine {
    pub assigned_number: String,
    pub call_count: u32,
}

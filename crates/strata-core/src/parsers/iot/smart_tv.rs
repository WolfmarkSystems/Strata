use crate::errors::ForensicError;

pub struct SmartTvParser;

impl Default for SmartTvParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SmartTvParser {
    pub fn new() -> Self {
        Self
    }

    /// Read application caches from Samsung Tizen and LG WebOS
    pub fn extract_viewing_history(&self, _tv_data: &[u8]) -> Result<Vec<TvEvent>, ForensicError> {
        Ok(vec![])
    }
}

pub struct TvEvent {
    pub timestamp: u64,
    pub app_id: String,
    pub action: String,
}

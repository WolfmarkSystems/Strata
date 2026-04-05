use crate::errors::ForensicError;

pub struct AltBrowserParser;

impl Default for AltBrowserParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AltBrowserParser {
    pub fn new() -> Self {
        Self
    }

    /// Pluck local profile caches from privacy-focused browsers (Tor Mobile, DuckDuckGo, Brave).
    pub fn extract_private_cache(
        &self,
        _browser_profile: &[u8],
    ) -> Result<Vec<PrivateHistory>, ForensicError> {
        Ok(vec![])
    }
}

pub struct PrivateHistory {
    pub url_hash: String,
    pub visit_time: u64,
}

use crate::errors::ForensicError;

pub struct TikTokParser;

impl TikTokParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse drafts.sqlite to recover unpublished media files.
    pub fn parse_drafts(&self, _db_data: &[u8]) -> Result<Vec<TikTokDraft>, ForensicError> {
        Ok(vec![])
    }

    /// Extrapolate the user's secret watch history and db_im.db inbox trace.
    pub fn analyze_watch_history(
        &self,
        _cache_data: &[u8],
    ) -> Result<Vec<TikTokEvent>, ForensicError> {
        Ok(vec![])
    }
}

pub struct TikTokDraft {
    pub temp_path: String,
    pub created: u64,
}
pub struct TikTokEvent {
    pub action: String,
    pub timestamp: u64,
    pub video_id: String,
}

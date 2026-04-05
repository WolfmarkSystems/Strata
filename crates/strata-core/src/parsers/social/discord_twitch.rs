use crate::errors::ForensicError;

pub struct DiscordTwitchParser;

impl Default for DiscordTwitchParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscordTwitchParser {
    pub fn new() -> Self {
        Self
    }

    /// Reconstruct cached Discord attachments sent in ephemeral DM systems.
    pub fn reconstruct_discord_cache(
        &self,
        _cache_dir: &[u8],
    ) -> Result<Vec<DiscordCacheItem>, ForensicError> {
        Ok(vec![])
    }

    /// Extract Twitch direct messages and subscriber viewing traces.
    pub fn extract_twitch_history(
        &self,
        _db_data: &[u8],
    ) -> Result<Vec<TwitchHistory>, ForensicError> {
        Ok(vec![])
    }
}

pub struct DiscordCacheItem {
    pub original_url: String,
    pub local_mapping: String,
}
pub struct TwitchHistory {
    pub channel: String,
    pub session_duration: u64,
}

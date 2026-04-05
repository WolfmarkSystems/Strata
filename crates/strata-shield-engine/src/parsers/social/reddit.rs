use crate::errors::ForensicError;

pub struct RedditParser;

impl RedditParser {
    pub fn new() -> Self {
        Self
    }

    /// Identify alt-tokens representing separate anonymous account switches.
    pub fn parse_account_switches(
        &self,
        _auth_data: &[u8],
    ) -> Result<Vec<RedditAccount>, ForensicError> {
        Ok(vec![])
    }

    /// Dump local device cached subreddit history without API hits.
    pub fn dump_subreddit_history(
        &self,
        _cache: &[u8],
    ) -> Result<Vec<SubredditVisit>, ForensicError> {
        Ok(vec![])
    }
}

pub struct RedditAccount {
    pub internal_id: String,
    pub handle: String,
}
pub struct SubredditVisit {
    pub sub: String,
    pub timestamp: u64,
}

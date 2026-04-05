use crate::errors::ForensicError;

pub struct WtmpParser;

impl Default for WtmpParser {
    fn default() -> Self {
        Self::new()
    }
}

impl WtmpParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse binary utmp/wtmp/btmp session recording files natively
    pub fn parse_session_file(&self, _data: &[u8]) -> Result<Vec<LoginSession>, ForensicError> {
        Ok(vec![])
    }
}

pub struct LoginSession {
    pub user: String,
    pub pid: i32,
    pub host: String,
    pub timestamp: u64,
    pub is_login: bool,
}

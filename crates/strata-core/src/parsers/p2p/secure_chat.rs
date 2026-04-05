use crate::errors::ForensicError;

pub struct SecureChatParser;

impl Default for SecureChatParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureChatParser {
    pub fn new() -> Self {
        Self
    }

    /// Map routing identities for Session (onion chat), Briar (mesh), and Matrix.
    pub fn locate_onion_identities(
        &self,
        _session_db: &[u8],
    ) -> Result<Vec<DecentralizedIdentity>, ForensicError> {
        Ok(vec![])
    }
}

pub struct DecentralizedIdentity {
    pub onion_hash: String,
    pub protocol: String,
}

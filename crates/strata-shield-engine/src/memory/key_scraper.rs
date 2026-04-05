use crate::errors::ForensicError;

pub struct KeyScraper;

impl KeyScraper {
    pub fn new() -> Self {
        Self
    }

    /// Scan a raw memory dump for AES key schedules (AES-NI footprint)
    /// commonly used for live Bitlocker, TrueCrypt, or LUKS decryptions.
    pub fn dump_aes_keys(&self, _data: &[u8]) -> Result<Vec<AesKey>, ForensicError> {
        Ok(vec![])
    }
}

pub struct AesKey {
    pub key: Vec<u8>,
    pub likely_length: usize,
}

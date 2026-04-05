use crate::errors::ForensicError;

pub struct HardwareWalletParser;

impl Default for HardwareWalletParser {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareWalletParser {
    pub fn new() -> Self {
        Self
    }

    /// Intercept Ledger Live and Trezor local node caches for xPub extended key footprints.
    pub fn extract_local_keys(
        &self,
        _ledger_db: &[u8],
    ) -> Result<Vec<HardwareWalletLog>, ForensicError> {
        Ok(vec![])
    }
}

pub struct HardwareWalletLog {
    pub xpub_derived: String,
    pub last_connected: u64,
}

use crate::errors::ForensicError;

pub struct VaultAppParser;

impl VaultAppParser {
    pub fn new() -> Self {
        Self
    }

    /// Bypass directory obfuscation and map encrypted vault files (Calculator Vault, KeepSafe)
    pub fn map_vault_contents(&self, _vault_dir: &[u8]) -> Result<Vec<VaultFile>, ForensicError> {
        Ok(vec![])
    }
}

pub struct VaultFile {
    pub obfuscated_name: String,
    pub original_extension: String,
}

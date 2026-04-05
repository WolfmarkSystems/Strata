use crate::errors::ForensicError;

pub struct ShimcacheParser;

impl Default for ShimcacheParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ShimcacheParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse Application Compatibility Cache (AppCompatCache) from the SYSTEM registry hive
    pub fn parse_shimcache(
        &self,
        _registry_data: &[u8],
        _windows_version: &str,
    ) -> Result<Vec<ShimcacheEntry>, ForensicError> {
        Ok(vec![])
    }
}

pub struct ShimcacheEntry {
    pub path: String,
    pub last_modified: u64,
    pub executed: bool,
}

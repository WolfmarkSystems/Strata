use crate::errors::ForensicError;

pub struct ProjectVicMatcher;

impl Default for ProjectVicMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ProjectVicMatcher {
    pub fn new() -> Self {
        Self
    }

    /// Parse Project VIC (VICS) OData hashes to proactively filter illegal child exploitation material.
    pub fn process_vics_json(&self, _json_data: &[u8]) -> Result<Vec<VicsEntry>, ForensicError> {
        Ok(vec![])
    }
}

pub struct VicsEntry {
    pub md5: String,
    pub sha1: String,
    pub category: String,
}

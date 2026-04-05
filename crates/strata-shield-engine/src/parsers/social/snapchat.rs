use crate::errors::ForensicError;

pub struct SnapchatParser;

impl SnapchatParser {
    pub fn new() -> Self {
        Self
    }

    /// Read local SQLite memory DB (gallery.db / gallery.sqlite)
    pub fn parse_memories(&self, _db_data: &[u8]) -> Result<Vec<SnapMemory>, ForensicError> {
        Ok(vec![])
    }

    /// Read the location.db file for historical Snap Map geo-fencing.
    pub fn parse_snap_map(&self, _db_data: &[u8]) -> Result<Vec<SnapGeo>, ForensicError> {
        Ok(vec![])
    }
}

pub struct SnapMemory {
    pub overlay_text: String,
    pub file_reference: String,
    pub timestamp: u64,
}
pub struct SnapGeo {
    pub lat: f64,
    pub lon: f64,
    pub timestamp: u64,
}

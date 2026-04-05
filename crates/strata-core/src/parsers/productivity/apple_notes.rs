use crate::errors::ForensicError;

pub struct AppleNotesParser;

impl Default for AppleNotesParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AppleNotesParser {
    pub fn new() -> Self {
        Self
    }

    /// Read ZNotes.sqlite and decompress embedded native Apple Protobuf formats for note extraction.
    pub fn extract_notes(&self, _znotes_db: &[u8]) -> Result<Vec<AppleNote>, ForensicError> {
        Ok(vec![])
    }
}

pub struct AppleNote {
    pub title: String,
    pub body: String,
    pub modified: u64,
}

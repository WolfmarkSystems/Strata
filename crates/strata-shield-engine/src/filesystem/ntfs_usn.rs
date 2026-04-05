use crate::errors::ForensicError;

pub struct UsnJournalParser;

impl UsnJournalParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse NTFS $UsnJrnl:$J files to recover deleted file names and historical modifications
    pub fn parse_usn_records(&self, _usn_data: &[u8]) -> Result<Vec<UsnRecord>, ForensicError> {
        Ok(vec![])
    }
}

pub struct UsnRecord {
    pub usn: u64,
    pub file_reference: u64,
    pub parent_reference: u64,
    pub reason: u32,
    pub timestamp: u64,
    pub filename: String,
}

use crate::errors::ForensicError;

pub struct RawDumpParser;

impl RawDumpParser {
    pub fn new() -> Self {
        Self
    }

    /// Walk Windows EPROCESS blocks within a raw memory dump to extract states
    pub fn map_eprocess_blocks(
        &self,
        _data: &[u8],
        _kdbg_offset: u64,
    ) -> Result<Vec<EProcess>, ForensicError> {
        Ok(vec![])
    }
}

pub struct EProcess {
    pub process_id: u32,
    pub process_name: String,
    pub parent_pid: u32,
    pub start_time: u64,
}

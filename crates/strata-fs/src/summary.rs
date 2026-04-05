use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// High-level filesystem type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilesystemType {
    Unknown,
    NTFS,
    FAT,
    ExFAT,
    EXT,
    APFS,
}

impl FilesystemType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FilesystemType::Unknown => "Unknown",
            FilesystemType::NTFS => "NTFS",
            FilesystemType::FAT => "FAT",
            FilesystemType::ExFAT => "exFAT",
            FilesystemType::EXT => "EXT",
            FilesystemType::APFS => "APFS",
        }
    }
}

/// Fast, metadata-only filesystem summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemSummary {
    pub filesystem: FilesystemType,

    /// Total number of files
    pub file_count: u64,

    /// Total number of directories
    pub directory_count: u64,

    /// Deleted entries (if detectable)
    pub deleted_count: u64,

    /// Earliest timestamp observed
    pub first_timestamp: Option<OffsetDateTime>,

    /// Latest timestamp observed
    pub last_timestamp: Option<OffsetDateTime>,
}

impl FilesystemSummary {
    /// Create an empty summary for a detected filesystem
    pub fn new(filesystem: FilesystemType) -> Self {
        Self {
            filesystem,
            file_count: 0,
            directory_count: 0,
            deleted_count: 0,
            first_timestamp: None,
            last_timestamp: None,
        }
    }

    /// Update the observed timestamp range
    pub fn observe_timestamp(&mut self, ts: OffsetDateTime) {
        match self.first_timestamp {
            None => self.first_timestamp = Some(ts),
            Some(existing) if ts < existing => self.first_timestamp = Some(ts),
            _ => {}
        }

        match self.last_timestamp {
            None => self.last_timestamp = Some(ts),
            Some(existing) if ts > existing => self.last_timestamp = Some(ts),
            _ => {}
        }
    }
}

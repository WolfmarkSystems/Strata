//! Shared types: the `EvidenceImage` trait, metadata struct, and
//! error enum every concrete image reader speaks.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Structured diagnostic emitted by an evidence reader when a read
/// silently succeeded (returned zero bytes, for example) but something
/// about the underlying image is worth surfacing to the examiner.
///
/// Added in v14/EWF-TRIM-WARN-1. Defaulted trait method means non-EWF
/// formats don't have to opt in; they return an empty vec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceWarning {
    /// The caller requested bytes at an offset that lies beyond the
    /// acquired range of the image. Most common cause: EWF chunk table
    /// advertises a logical disk larger than was actually captured
    /// (aka "acquisition trim"). The reader returned zeros so the
    /// caller can keep walking, but the bytes are not real evidence.
    OffsetBeyondAcquired {
        requested_offset: u64,
        acquired_ceiling: u64,
        segment_count: u32,
    },
    /// A chunk-table entry points at an offset that is not inside its
    /// declared segment. Indicates a corrupt or tampered chunk table.
    ChunkOffsetInvalid {
        chunk_number: u64,
        stored_offset: u64,
    },
    /// The computed hash for the image does not match the stored hash
    /// in the acquisition metadata. Informational — does not short-
    /// circuit reads.
    HashMismatch {
        expected: String,
        observed: String,
        algorithm: String,
    },
}

/// Read-only byte-oriented view of a forensic image. Every concrete
/// reader (Raw, E01, VMDK, VHD, VHDX, DMG) implements this trait.
///
/// Implementations MUST be safe to use across threads (`Send + Sync`)
/// and MUST enforce read-only semantics — forensic integrity is
/// non-negotiable.
pub trait EvidenceImage: Send + Sync {
    /// Total logical disk size in bytes.
    fn size(&self) -> u64;

    /// Read from the image at `offset`. Returns the number of bytes
    /// actually read, which may be less than `buf.len()` near EOF.
    /// Reading past EOF returns `0` — never an error.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> EvidenceResult<usize>;

    /// Logical sector size in bytes (typically 512 or 4096).
    fn sector_size(&self) -> u32;

    /// Stable format name for reporting ("Raw" / "E01" / "VMDK" / …).
    fn format_name(&self) -> &'static str;

    /// Acquisition metadata where available.
    fn metadata(&self) -> ImageMetadata;

    /// Structured warnings accumulated during reads. Defaulted to an
    /// empty vec so non-EWF formats don't need to opt in. E01Image
    /// populates this with `OffsetBeyondAcquired` for reads past the
    /// acquired chunk range.
    fn warnings(&self) -> Vec<EvidenceWarning> {
        Vec::new()
    }
}

/// Acquisition metadata. All fields optional — E01 populates most,
/// raw dd populates only the size/sector/format triple.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMetadata {
    pub format: String,
    pub size_bytes: u64,
    pub sector_size: u32,
    pub examiner: Option<String>,
    pub case_number: Option<String>,
    pub evidence_number: Option<String>,
    pub acquisition_date: Option<DateTime<Utc>>,
    pub acquisition_tool: Option<String>,
    pub acquisition_hash_md5: Option<String>,
    pub acquisition_hash_sha256: Option<String>,
    pub notes: Option<String>,
}

impl ImageMetadata {
    pub fn minimal(format: &str, size_bytes: u64, sector_size: u32) -> Self {
        Self {
            format: format.into(),
            size_bytes,
            sector_size,
            examiner: None,
            case_number: None,
            evidence_number: None,
            acquisition_date: None,
            acquisition_tool: None,
            acquisition_hash_md5: None,
            acquisition_hash_sha256: None,
            notes: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported image format: {0}")]
    UnknownFormat(PathBuf),
    #[error("invalid {format} header: {reason}")]
    InvalidHeader {
        format: &'static str,
        reason: String,
    },
    #[error("invalid MBR partition table")]
    NoValidMbr,
    #[error("invalid GPT partition table")]
    NoValidGpt,
    #[error("hash verification failed: stored={stored}, computed={computed}")]
    HashMismatch { stored: String, computed: String },
    #[error("{0}")]
    Other(String),
}

pub type EvidenceResult<T> = Result<T, EvidenceError>;

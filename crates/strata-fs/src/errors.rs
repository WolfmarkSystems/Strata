use thiserror::Error;

#[derive(Debug, Error)]
pub enum ForensicError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid image format")]
    InvalidImageFormat,

    #[error("Unsupported filesystem")]
    UnsupportedFilesystem,

    #[error("Unsupported image format: {0}")]
    UnsupportedImageFormat(String),

    #[error("Read offset is not sector-aligned")]
    InvalidOffset,

    #[error("Read length is not a multiple of sector size")]
    InvalidLength,

    #[error("Partition not found: {0}")]
    PartitionNotFound(u32),

    #[error("Filesystem not detected")]
    FilesystemNotDetected,

    #[error("Encryption detected")]
    EncryptionDetected,

    #[error("Hash computation failed")]
    HashComputationFailed,

    #[error("Audit error")]
    AuditError,

    #[error("Corrupt data at offset {0}")]
    CorruptData(u64),

    #[error("Out of range: {0}")]
    OutOfRange(String),

    #[error("Malformed Data: {0}")]
    MalformedData(String),

    #[error("Unsupported Parser: {0}")]
    UnsupportedParser(String),

    #[error("Container error: {0}")]
    Container(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Not found: {0}")]
    NotFound(String),
}

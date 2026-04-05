use crate::audit::event::AuditEventType;
use crate::audit::logger::AuditLogger;
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;
use tracing::{error, warn};

use blake3::Hasher as Blake3Hasher;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest as ShaDigest, Sha256};

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

type ChunkHashResult = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

pub fn hash_bytes(data: &[u8]) -> HashResults {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut blake3 = Blake3Hasher::new();

    md5.update(data);
    sha1.update(data);
    sha256.update(data);
    blake3.update(data);

    HashResults {
        md5: Some(format!("{:x}", md5.finalize())),
        sha1: Some(format!("{:x}", sha1.finalize())),
        sha256: Some(format!("{:x}", sha256.finalize())),
        blake3: Some(format!("{}", blake3.finalize())),
    }
}

pub type HashProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;

#[derive(Debug, Clone)]
pub struct HashResults {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub blake3: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HashOptions {
    pub allow_partial_final: bool,
    #[cfg(feature = "turbo")]
    pub use_blake3: bool,
}

#[cfg(feature = "turbo")]
impl HashOptions {
    pub fn turbo() -> Self {
        Self {
            allow_partial_final: false,
            use_blake3: true,
        }
    }
}

pub fn hash_container(
    container: &dyn EvidenceContainerRO,
    options: HashOptions,
) -> Result<HashResults, ForensicError> {
    #[cfg(feature = "turbo")]
    if options.use_blake3 {
        return hash_container_blake3(container, options);
    }

    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut blake3 = Blake3Hasher::new();

    let sector = container.sector_size();
    let size = container.size();

    if sector == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    if !options.allow_partial_final && !size.is_multiple_of(sector) {
        return Err(ForensicError::InvalidImageFormat);
    }

    let mut offset = 0u64;

    while offset < size {
        let mut len = 8u64 * 1024 * 1024;
        let remaining = size - offset;
        if len > remaining {
            len = remaining;
        }

        if !len.is_multiple_of(sector) && offset + len != size {
            len -= len % sector;
            if len == 0 {
                len = remaining;
            }
        }

        if (offset + len == size) && !len.is_multiple_of(sector) && !options.allow_partial_final {
            return Err(ForensicError::InvalidLength);
        }

        let data = container.read_at(offset, len)?;

        md5.update(&data);
        sha1.update(&data);
        sha256.update(&data);
        blake3.update(&data);

        offset += len;
    }

    Ok(HashResults {
        md5: Some(format!("{:x}", md5.finalize())),
        sha1: Some(format!("{:x}", sha1.finalize())),
        sha256: Some(format!("{:x}", sha256.finalize())),
        blake3: Some(format!("{}", blake3.finalize())),
    })
}

#[cfg(feature = "turbo")]
fn hash_container_blake3(
    container: &dyn EvidenceContainerRO,
    options: HashOptions,
) -> Result<HashResults, ForensicError> {
    let mut blake3 = Blake3Hasher::new();
    let mut sha256 = Sha256::new();

    let sector = container.sector_size();
    let size = container.size();

    if sector == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    if !options.allow_partial_final && !size.is_multiple_of(sector) {
        return Err(ForensicError::InvalidImageFormat);
    }

    let mut offset = 0u64;

    while offset < size {
        let mut len = 16u64 * 1024 * 1024;
        let remaining = size - offset;
        if len > remaining {
            len = remaining;
        }

        if !len.is_multiple_of(sector) && offset + len != size {
            len -= len % sector;
            if len == 0 {
                len = remaining;
            }
        }

        if (offset + len == size) && !len.is_multiple_of(sector) && !options.allow_partial_final {
            return Err(ForensicError::InvalidLength);
        }

        let data = container.read_at(offset, len)?;

        blake3.update(&data);
        sha256.update(&data);

        offset += len;
    }

    Ok(HashResults {
        md5: None,
        sha1: None,
        sha256: Some(format!("{:x}", sha256.finalize())),
        blake3: Some(format!("{}", blake3.finalize())),
    })
}

pub fn hash_container_with_progress(
    container: &dyn EvidenceContainerRO,
    options: HashOptions,
    progress: Option<HashProgressCallback>,
) -> Result<HashResults, ForensicError> {
    #[cfg(feature = "turbo")]
    if options.use_blake3 {
        return hash_container_blake3_with_progress(container, options, progress);
    }

    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut blake3 = Blake3Hasher::new();

    let sector = container.sector_size();
    let size = container.size();

    if sector == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    if !options.allow_partial_final && !size.is_multiple_of(sector) {
        return Err(ForensicError::InvalidImageFormat);
    }

    let mut offset = 0u64;

    while offset < size {
        let mut len = 8u64 * 1024 * 1024;
        let remaining = size - offset;
        if len > remaining {
            len = remaining;
        }

        if !len.is_multiple_of(sector) && offset + len != size {
            len -= len % sector;
            if len == 0 {
                len = remaining;
            }
        }

        if (offset + len == size) && !len.is_multiple_of(sector) && !options.allow_partial_final {
            return Err(ForensicError::InvalidLength);
        }

        let data = container.read_at(offset, len)?;

        md5.update(&data);
        sha1.update(&data);
        sha256.update(&data);
        blake3.update(&data);

        offset += len;

        if let Some(ref cb) = progress {
            cb(offset, size);
        }
    }

    Ok(HashResults {
        md5: Some(format!("{:x}", md5.finalize())),
        sha1: Some(format!("{:x}", sha1.finalize())),
        sha256: Some(format!("{:x}", sha256.finalize())),
        blake3: Some(format!("{}", blake3.finalize())),
    })
}

#[cfg(feature = "turbo")]
fn hash_container_blake3_with_progress(
    container: &dyn EvidenceContainerRO,
    options: HashOptions,
    progress: Option<HashProgressCallback>,
) -> Result<HashResults, ForensicError> {
    let mut blake3 = Blake3Hasher::new();
    let mut sha256 = Sha256::new();

    let sector = container.sector_size();
    let size = container.size();

    if sector == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    if !options.allow_partial_final && !size.is_multiple_of(sector) {
        return Err(ForensicError::InvalidImageFormat);
    }

    let mut offset = 0u64;

    while offset < size {
        let mut len = 16u64 * 1024 * 1024;
        let remaining = size - offset;
        if len > remaining {
            len = remaining;
        }

        if !len.is_multiple_of(sector) && offset + len != size {
            len -= len % sector;
            if len == 0 {
                len = remaining;
            }
        }

        if (offset + len == size) && !len.is_multiple_of(sector) && !options.allow_partial_final {
            return Err(ForensicError::InvalidLength);
        }

        let data = container.read_at(offset, len)?;

        blake3.update(&data);
        sha256.update(&data);

        offset += len;

        if let Some(ref cb) = progress {
            cb(offset, size);
        }
    }

    Ok(HashResults {
        md5: None,
        sha1: None,
        sha256: Some(format!("{:x}", sha256.finalize())),
        blake3: Some(format!("{}", blake3.finalize())),
    })
}

pub fn hash_container_audited(
    container: &dyn EvidenceContainerRO,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
    options: HashOptions,
) -> Result<HashResults, ForensicError> {
    let size = container.size();
    let sector = container.sector_size();

    if sector == 0 {
        audit.log(
            case_id,
            AuditEventType::Error {
                message: "Hashing: sector_size is zero (invalid evidence container)".to_string(),
            },
        );
        return Err(ForensicError::InvalidImageFormat);
    }

    if !size.is_multiple_of(sector) {
        if options.allow_partial_final {
            audit.log(
                case_id,
                AuditEventType::Warning {
                    message: format!(
                        "Hashing: evidence size ({}) is not a multiple of sector_size ({}); allowing partial final read at EOF",
                        size, sector
                    ),
                },
            );
        } else {
            audit.log(
                case_id,
                AuditEventType::Error {
                    message: format!(
                        "Hashing refused: evidence size ({}) is not a multiple of sector_size ({})",
                        size, sector
                    ),
                },
            );
            return Err(ForensicError::InvalidImageFormat);
        }
    }

    let results = hash_container(container, options)?;

    audit.log(
        case_id,
        AuditEventType::HashComputed {
            md5: results.md5.clone(),
            sha1: results.sha1.clone(),
            sha256: results.sha256.clone(),
        },
    );

    Ok(results)
}

pub fn hash_container_audited_with_progress(
    container: &dyn EvidenceContainerRO,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
    options: HashOptions,
    progress: Option<HashProgressCallback>,
) -> Result<HashResults, ForensicError> {
    let size = container.size();
    let sector = container.sector_size();

    if sector == 0 {
        audit.log(
            case_id,
            AuditEventType::Error {
                message: "Hashing: sector_size is zero (invalid evidence container)".to_string(),
            },
        );
        return Err(ForensicError::InvalidImageFormat);
    }

    if !size.is_multiple_of(sector) {
        if options.allow_partial_final {
            audit.log(
                case_id,
                AuditEventType::Warning {
                    message: format!(
                        "Hashing: evidence size ({}) is not a multiple of sector_size ({}); allowing partial final read at EOF",
                        size, sector
                    ),
                },
            );
        } else {
            audit.log(
                case_id,
                AuditEventType::Error {
                    message: format!(
                        "Hashing refused: evidence size ({}) is not a multiple of sector_size ({})",
                        size, sector
                    ),
                },
            );
            return Err(ForensicError::InvalidImageFormat);
        }
    }

    let results = hash_container_with_progress(container, options, progress)?;

    audit.log(
        case_id,
        AuditEventType::HashComputed {
            md5: results.md5.clone(),
            sha1: results.sha1.clone(),
            sha256: results.sha256.clone(),
        },
    );

    Ok(results)
}

#[cfg(feature = "parallel")]
pub fn hash_container_parallel(
    container: &dyn EvidenceContainerRO,
    options: HashOptions,
    _num_threads: usize,
) -> Result<HashResults, ForensicError> {
    use rayon::prelude::*;

    let sector = container.sector_size();
    let size = container.size();

    if sector == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    if !options.allow_partial_final && !size.is_multiple_of(sector) {
        return Err(ForensicError::InvalidImageFormat);
    }

    #[cfg(feature = "turbo")]
    if options.use_blake3 {
        return hash_container_parallel_blake3(container, options);
    }

    let chunk_size = 16u64 * 1024 * 1024;
    let num_chunks = size.div_ceil(chunk_size) as usize;

    let chunks: Vec<(u64, u64)> = (0..num_chunks)
        .map(|i| {
            let offset = i as u64 * chunk_size;
            let len = chunk_size.min(size - offset);
            (offset, len)
        })
        .collect();

    let results: Vec<ChunkHashResult> = chunks
        .par_iter()
        .with_max_len(1)
        .map(|(offset, len)| {
            let data = container.read_at(*offset, *len).unwrap_or_default();

            let mut md5 = Md5::new();
            let mut sha1 = Sha1::new();
            let mut sha256 = Sha256::new();
            let mut blake3 = Blake3Hasher::new();

            md5.update(&data);
            sha1.update(&data);
            sha256.update(&data);
            blake3.update(&data);

            (
                md5.finalize().to_vec(),
                sha1.finalize().to_vec(),
                sha256.finalize().to_vec(),
                blake3.finalize().as_bytes().to_vec(),
            )
        })
        .collect();

    let mut final_md5 = Md5::new();
    let mut final_sha1 = Sha1::new();
    let mut final_sha256 = Sha256::new();
    let mut final_blake3 = Blake3Hasher::new();

    for (md5, sha1, sha256, _blake3) in results {
        final_md5.update(&md5);
        final_sha1.update(&sha1);
        final_sha256.update(&sha256);
        final_blake3.update(&md5);
        final_blake3.update(&sha1);
        final_blake3.update(&sha256);
    }

    Ok(HashResults {
        md5: Some(format!("{:x}", final_md5.finalize())),
        sha1: Some(format!("{:x}", final_sha1.finalize())),
        sha256: Some(format!("{:x}", final_sha256.finalize())),
        blake3: Some(format!("{}", final_blake3.finalize())),
    })
}

#[cfg(all(feature = "parallel", feature = "turbo"))]
fn hash_container_parallel_blake3(
    container: &dyn EvidenceContainerRO,
    options: HashOptions,
) -> Result<HashResults, ForensicError> {
    use rayon::prelude::*;

    let sector = container.sector_size();
    let size = container.size();

    if sector == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    if !options.allow_partial_final && !size.is_multiple_of(sector) {
        return Err(ForensicError::InvalidImageFormat);
    }

    let chunk_size = 32u64 * 1024 * 1024;
    let num_chunks = size.div_ceil(chunk_size) as usize;

    let chunks: Vec<(u64, u64)> = (0..num_chunks)
        .map(|i| {
            let offset = i as u64 * chunk_size;
            let len = chunk_size.min(size - offset);
            (offset, len)
        })
        .collect();

    let blake3_parts: Vec<Vec<u8>> = chunks
        .par_iter()
        .with_max_len(1)
        .map(|(offset, len)| {
            let data = container.read_at(*offset, *len).unwrap_or_default();
            let mut hasher = Blake3Hasher::new();
            hasher.update(&data);
            hasher.finalize().as_bytes().to_vec()
        })
        .collect();

    let mut final_blake3 = Blake3Hasher::new();
    for part in &blake3_parts {
        final_blake3.update(part);
    }
    let blake3_hex = format!("{}", final_blake3.finalize());

    drop(blake3_parts);

    let mut final_sha256 = Sha256::new();
    for (offset, len) in &chunks {
        let data = container.read_at(*offset, *len).unwrap_or_default();
        let mut sha = Sha256::new();
        sha.update(&data);
        final_sha256.update(&sha.finalize());
    }

    Ok(HashResults {
        md5: None,
        sha1: None,
        sha256: Some(format!("{:x}", final_sha256.finalize())),
        blake3: Some(blake3_hex),
    })
}

use crate::events::{EngineEvent, EngineEventKind, EventBus, EventSeverity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Hash computation failed: {0}")]
    Computation(String),
    #[error("Path does not exist: {0}")]
    PathNotFound(String),
    #[error("Not a file: {0}")]
    NotAFile(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FileCategory {
    KnownGood,
    Unknown,
    KnownBad,
    Changed,
    OSArtifact,
}

impl std::fmt::Display for FileCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileCategory::KnownGood => write!(f, "KnownGood"),
            FileCategory::Unknown => write!(f, "Unknown"),
            FileCategory::KnownBad => write!(f, "KnownBad"),
            FileCategory::Changed => write!(f, "Changed"),
            FileCategory::OSArtifact => write!(f, "OSArtifact"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileHashResult {
    pub path: PathBuf,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: String,
    pub blake3: Option<String>,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
    pub category: Option<FileCategory>,
}

impl FileHashResult {
    pub fn new(path: PathBuf, sha256: String, size: u64, modified: Option<DateTime<Utc>>) -> Self {
        Self {
            path,
            md5: None,
            sha1: None,
            sha256,
            blake3: None,
            size,
            modified,
            category: None,
        }
    }

    pub fn with_additional_hashes(mut self, md5: Option<String>, sha1: Option<String>) -> Self {
        self.md5 = md5;
        self.sha1 = sha1;
        self
    }

    pub fn with_blake3(mut self, blake3: String) -> Self {
        self.blake3 = Some(blake3);
        self
    }

    pub fn with_category(mut self, category: FileCategory) -> Self {
        self.category = Some(category);
        self
    }
}

pub fn hash_file(path: &Path) -> Result<FileHashResult, HashError> {
    if !path.exists() {
        return Err(HashError::PathNotFound(path.display().to_string()));
    }

    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(HashError::NotAFile(path.display().to_string()));
    }

    let mut file = File::open(path)?;
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut hasher = Sha256::new();
    let mut blake3 = Blake3Hasher::new();
    let mut buffer = [0u8; 131072];

    let size = metadata.len();

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        md5.update(&buffer[..bytes_read]);
        sha1.update(&buffer[..bytes_read]);
        hasher.update(&buffer[..bytes_read]);
        blake3.update(&buffer[..bytes_read]);
    }

    let md5_hex = format!("{:x}", md5.finalize());
    let sha1_hex = format!("{:x}", sha1.finalize());
    let sha256 = format!("{:x}", hasher.finalize());
    let blake3_hex = format!("{}", blake3.finalize());

    let modified = metadata.modified().ok().map(DateTime::<Utc>::from);

    Ok(
        FileHashResult::new(path.to_path_buf(), sha256, size, modified)
            .with_additional_hashes(Some(md5_hex), Some(sha1_hex))
            .with_blake3(blake3_hex),
    )
}

#[cfg(feature = "turbo")]
pub fn hash_file_turbo(path: &Path) -> Result<FileHashResult, HashError> {
    if !path.exists() {
        return Err(HashError::PathNotFound(path.display().to_string()));
    }

    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(HashError::NotAFile(path.display().to_string()));
    }

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut blake3 = Blake3Hasher::new();
    let mut buffer = [0u8; 262144];

    let size = metadata.len();

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
        blake3.update(&buffer[..bytes_read]);
    }

    let sha256 = format!("{:x}", hasher.finalize());
    let blake3_hex = format!("{}", blake3.finalize());

    let modified = metadata.modified().ok().map(|t| DateTime::<Utc>::from(t));

    Ok(FileHashResult::new(path.to_path_buf(), sha256, size, modified).with_blake3(blake3_hex))
}

#[cfg(feature = "parallel")]
pub fn hash_files_parallel(
    paths: Vec<PathBuf>,
    event_bus: Arc<EventBus>,
    case_id: Option<String>,
    job_id: &str,
) -> Vec<Result<FileHashResult, HashError>> {
    use rayon::prelude::*;

    let total = paths.len();
    let processed = Arc::new(AtomicUsize::new(0));
    let last_emit = Arc::new(AtomicUsize::new(0));

    let results: Vec<Result<FileHashResult, HashError>> = paths
        .par_iter()
        .map(|path| {
            let result = hash_file(path);

            let count = processed.fetch_add(1, Ordering::Relaxed) + 1;

            let last = last_emit.load(Ordering::Relaxed);
            if count - last >= 100 || count == total {
                last_emit.store(count, Ordering::Relaxed);
                let progress = (count as f32 / total as f32) * 100.0;

                event_bus.emit(EngineEvent::new(
                    case_id.clone(),
                    EngineEventKind::JobProgress {
                        job_id: job_id.to_string(),
                        job_type: "file_hashing".to_string(),
                        progress,
                        message: format!("Hashed {}/{} files", count, total),
                    },
                    EventSeverity::Info,
                    format!("Hashing: {}/{} files", count, total),
                ));
            }

            result
        })
        .collect();

    event_bus.emit(EngineEvent::new(
        case_id,
        EngineEventKind::JobProgress {
            job_id: job_id.to_string(),
            job_type: "file_hashing".to_string(),
            progress: 100.0,
            message: format!("Completed hashing {} files", total),
        },
        EventSeverity::Info,
        format!("Hashing complete: {} files", total),
    ));

    results
}

#[cfg(not(feature = "parallel"))]
pub fn hash_files_parallel(
    paths: Vec<PathBuf>,
    event_bus: Arc<EventBus>,
    case_id: Option<String>,
    job_id: &str,
) -> Vec<Result<FileHashResult, HashError>> {
    let total = paths.len();
    let mut results = Vec::with_capacity(total);

    for (i, path) in paths.into_iter().enumerate() {
        let result = hash_file(&path);
        results.push(result);

        if i > 0 && i % 100 == 0 || i == total - 1 {
            let progress = ((i + 1) as f32 / total as f32) * 100.0;
            event_bus.emit(EngineEvent::new(
                case_id.clone(),
                EngineEventKind::JobProgress {
                    job_id: job_id.to_string(),
                    job_type: "file_hashing".to_string(),
                    progress,
                    message: format!("Hashed {}/{} files", i + 1, total),
                },
                EventSeverity::Info,
                format!("Hashing: {}/{} files", i + 1, total),
            ));
        }
    }

    event_bus.emit(EngineEvent::new(
        case_id,
        EngineEventKind::JobProgress {
            job_id: job_id.to_string(),
            job_type: "file_hashing".to_string(),
            progress: 100.0,
            message: format!("Completed hashing {} files", total),
        },
        EventSeverity::Info,
        format!("Hashing complete: {} files", total),
    ));

    results
}

use crate::hashset::SqliteHashSetManager;

#[cfg(feature = "parallel")]
pub fn hash_and_categorize_parallel(
    paths: Vec<PathBuf>,
    manager: &SqliteHashSetManager,
    event_bus: Arc<EventBus>,
    case_id: Option<String>,
    job_id: &str,
) -> Vec<FileHashResult> {
    #[cfg(feature = "turbo")]
    {
        hash_and_categorize_parallel_turbo(paths, manager, event_bus, case_id, job_id)
    }
    #[cfg(not(feature = "turbo"))]
    {
        hash_and_categorize_parallel_standard(paths, manager, event_bus, case_id, job_id)
    }
}

#[cfg(all(feature = "parallel", feature = "turbo"))]
fn hash_and_categorize_parallel_turbo(
    paths: Vec<PathBuf>,
    manager: &SqliteHashSetManager,
    event_bus: Arc<EventBus>,
    case_id: Option<String>,
    job_id: &str,
) -> Vec<FileHashResult> {
    use rayon::prelude::*;

    let total = paths.len();
    let processed = Arc::new(AtomicUsize::new(0));
    let last_emit = Arc::new(AtomicUsize::new(0));

    let results: Vec<FileHashResult> = paths
        .par_iter()
        .filter_map(|path| {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hash_file_turbo(path)));

            let result = match result {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    warn!("Failed to hash file {:?}: {:?}", path, e);
                    return None;
                }
                Err(panic_val) => {
                    let msg = if let Some(s) = panic_val.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_val.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "Unknown panic".to_string()
                    };
                    error!("PANIC while hashing {:?}: {}", path, msg);
                    return None;
                }
            };

            let category = manager.categorize_with_path(&result);
            let mut categorized = result;
            categorized.category = Some(category);

            let count = processed.fetch_add(1, Ordering::Relaxed) + 1;

            let last = last_emit.load(Ordering::Relaxed);
            if count - last >= 1000 || count == total {
                last_emit.store(count, Ordering::Relaxed);
                let progress = (count as f32 / total as f32) * 100.0;

                event_bus.emit(EngineEvent::new(
                    case_id.clone(),
                    EngineEventKind::JobProgress {
                        job_id: job_id.to_string(),
                        job_type: "file_hashing_turbo".to_string(),
                        progress,
                        message: format!("Hashed {}/{} files (turbo)", count, total),
                    },
                    EventSeverity::Info,
                    format!("Turbo hashing: {}/{} files", count, total),
                ));
            }

            Some(categorized)
        })
        .collect();

    event_bus.emit(EngineEvent::new(
        case_id.clone(),
        EngineEventKind::JobProgress {
            job_id: job_id.to_string(),
            job_type: "file_hashing_turbo".to_string(),
            progress: 100.0,
            message: format!("Completed turbo hashing {} files", total),
        },
        EventSeverity::Info,
        format!("Turbo hashing complete: {} files", total),
    ));

    results
}

#[cfg(feature = "parallel")]
#[cfg(not(feature = "turbo"))]
fn hash_and_categorize_parallel_standard(
    paths: Vec<PathBuf>,
    manager: &SqliteHashSetManager,
    event_bus: Arc<EventBus>,
    case_id: Option<String>,
    job_id: &str,
) -> Vec<FileHashResult> {
    use rayon::prelude::*;

    let total = paths.len();
    let processed = Arc::new(AtomicUsize::new(0));
    let last_emit = Arc::new(AtomicUsize::new(0));

    let results: Vec<FileHashResult> = paths
        .par_iter()
        .filter_map(|path| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hash_file(path)));

            let result = match result {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    warn!("Failed to hash file {:?}: {:?}", path, e);
                    return None;
                }
                Err(panic_val) => {
                    let msg = if let Some(s) = panic_val.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_val.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "Unknown panic".to_string()
                    };
                    error!("PANIC while hashing {:?}: {}", path, msg);
                    return None;
                }
            };

            let category = manager.categorize_with_path(&result);
            let mut categorized = result;
            categorized.category = Some(category);

            let count = processed.fetch_add(1, Ordering::Relaxed) + 1;

            let last = last_emit.load(Ordering::Relaxed);
            if count - last >= 100 || count == total {
                last_emit.store(count, Ordering::Relaxed);
                let progress = (count as f32 / total as f32) * 100.0;

                event_bus.emit(EngineEvent::new(
                    case_id.clone(),
                    EngineEventKind::JobProgress {
                        job_id: job_id.to_string(),
                        job_type: "file_hashing".to_string(),
                        progress,
                        message: format!("Hashed {}/{} files", count, total),
                    },
                    EventSeverity::Info,
                    format!("Hashing: {}/{} files", count, total),
                ));
            }

            Some(categorized)
        })
        .collect();

    event_bus.emit(EngineEvent::new(
        case_id,
        EngineEventKind::JobProgress {
            job_id: job_id.to_string(),
            job_type: "file_hashing".to_string(),
            progress: 100.0,
            message: format!("Completed hashing {} files", total),
        },
        EventSeverity::Info,
        format!("Hashing complete: {} files", total),
    ));

    results
}

#[cfg(not(feature = "parallel"))]
pub fn hash_and_categorize_parallel(
    paths: Vec<PathBuf>,
    manager: &SqliteHashSetManager,
    event_bus: Arc<EventBus>,
    case_id: Option<String>,
    job_id: &str,
) -> Vec<FileHashResult> {
    #[cfg(feature = "turbo")]
    return hash_and_categorize_sequential_turbo(paths, manager, event_bus, case_id, job_id);

    #[cfg(not(feature = "turbo"))]
    return hash_and_categorize_sequential_standard(paths, manager, event_bus, case_id, job_id);
}

#[cfg(all(not(feature = "parallel"), feature = "turbo"))]
fn hash_and_categorize_sequential_turbo(
    paths: Vec<PathBuf>,
    manager: &SqliteHashSetManager,
    event_bus: Arc<EventBus>,
    case_id: Option<String>,
    job_id: &str,
) -> Vec<FileHashResult> {
    let total = paths.len();
    let mut results = Vec::with_capacity(total);

    for (i, path) in paths.into_iter().enumerate() {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hash_file_turbo(&path)));

        match result {
            Ok(Ok(result)) => {
                let category = manager.categorize_with_path(&result);
                let mut categorized = result;
                categorized.category = Some(category);
                results.push(categorized);
            }
            Ok(Err(e)) => {
                warn!("Failed to hash file {:?}: {:?}", path, e);
            }
            Err(panic_val) => {
                let msg = if let Some(s) = panic_val.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_val.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };
                error!("PANIC while hashing {:?}: {}", path, msg);
            }
        }

        if i > 0 && i % 1000 == 0 || i == total - 1 {
            let progress = ((i + 1) as f32 / total as f32) * 100.0;
            event_bus.emit(EngineEvent::new(
                case_id.clone(),
                EngineEventKind::JobProgress {
                    job_id: job_id.to_string(),
                    job_type: "file_hashing_turbo".to_string(),
                    progress,
                    message: format!("Hashed {}/{} files (turbo)", i + 1, total),
                },
                EventSeverity::Info,
                format!("Turbo hashing: {}/{} files", i + 1, total),
            ));
        }
    }

    event_bus.emit(EngineEvent::new(
        case_id,
        EngineEventKind::JobProgress {
            job_id: job_id.to_string(),
            job_type: "file_hashing_turbo".to_string(),
            progress: 100.0,
            message: format!("Completed turbo hashing {} files", total),
        },
        EventSeverity::Info,
        format!("Turbo hashing complete: {} files", total),
    ));

    results
}

#[cfg(not(feature = "parallel"))]
#[cfg(not(feature = "turbo"))]
fn hash_and_categorize_sequential_standard(
    paths: Vec<PathBuf>,
    manager: &SqliteHashSetManager,
    event_bus: Arc<EventBus>,
    case_id: Option<String>,
    job_id: &str,
) -> Vec<FileHashResult> {
    let total = paths.len();
    let mut results = Vec::with_capacity(total);

    for (i, path) in paths.into_iter().enumerate() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hash_file(&path)));

        match result {
            Ok(Ok(result)) => {
                let category = manager.categorize_with_path(&result);
                let mut categorized = result;
                categorized.category = Some(category);
                results.push(categorized);
            }
            Ok(Err(e)) => {
                warn!("Failed to hash file {:?}: {:?}", path, e);
            }
            Err(panic_val) => {
                let msg = if let Some(s) = panic_val.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_val.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };
                error!("PANIC while hashing {:?}: {}", path, msg);
            }
        }

        if i > 0 && i % 100 == 0 || i == total - 1 {
            let progress = ((i + 1) as f32 / total as f32) * 100.0;
            event_bus.emit(EngineEvent::new(
                case_id.clone(),
                EngineEventKind::JobProgress {
                    job_id: job_id.to_string(),
                    job_type: "file_hashing".to_string(),
                    progress,
                    message: format!("Hashed {}/{} files", i + 1, total),
                },
                EventSeverity::Info,
                format!("Hashing: {}/{} files", i + 1, total),
            ));
        }
    }

    event_bus.emit(EngineEvent::new(
        case_id,
        EngineEventKind::JobProgress {
            job_id: job_id.to_string(),
            job_type: "file_hashing".to_string(),
            progress: 100.0,
            message: format!("Completed hashing {} files", total),
        },
        EventSeverity::Info,
        format!("Hashing complete: {} files", total),
    ));

    results
}

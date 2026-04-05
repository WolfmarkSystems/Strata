use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;
use crate::audit::logger::AuditLogger;
use crate::audit::event::AuditEventType;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum FileSystem {
    NTFS,
    FAT32,
    exFAT,
    Unknown,
}

impl FileSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileSystem::NTFS => "NTFS",
            FileSystem::FAT32 => "FAT32",
            FileSystem::exFAT => "exFAT",
            FileSystem::Unknown => "Unknown",
        }
    }
}

/// Detect filesystem using minimal, safe reads
pub fn detect_filesystem<C: EvidenceContainerRO>(
    container: &C,
    case_id: Uuid,
    audit: &AuditLogger,
) -> Result<FileSystem, ForensicError> {

    // Read up to first 512 bytes, or less if file is smaller
    let max_read = 512u64.min(container.size());
    let header = container.read_at(0, max_read)?;

    let fs = if header.len() >= 11 && &header[3..11] == b"NTFS    " {
        FileSystem::NTFS
    } else if header.len() >= 87 && &header[82..87] == b"FAT32" {
        FileSystem::FAT32
    } else if header.len() >= 8 && &header[3..8] == b"EXFAT" {
        FileSystem::exFAT
    } else {
        FileSystem::Unknown
    };

    // 🔐 Audit filesystem detection
    audit.log(
        case_id,
        AuditEventType::FilesystemDetected {
            filesystem: fs.as_str().to_string(),
        },
    );

    Ok(fs)
}

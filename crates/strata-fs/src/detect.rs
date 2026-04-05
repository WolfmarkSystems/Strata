use crate::audit::event::AuditEventType;
use crate::audit::logger::AuditLogger;
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileSystem {
    NTFS,
    FAT32,
    ExFAT,
    XFS,
    Btrfs,
    Unknown,
}

impl FileSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileSystem::NTFS => "NTFS",
            FileSystem::FAT32 => "FAT32",
            FileSystem::ExFAT => "exFAT",
            FileSystem::XFS => "XFS",
            FileSystem::Btrfs => "Btrfs",
            FileSystem::Unknown => "Unknown",
        }
    }
}

/// Detect filesystem using minimal reads at a given base offset.
/// Reads one sector (or remaining bytes if smaller than a sector).
pub fn detect_filesystem_at<C: EvidenceContainerRO>(
    container: &C,
    base_offset: u64,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
) -> Result<FileSystem, ForensicError> {
    let sector_size = container.sector_size();
    let max_len = container.size().saturating_sub(base_offset);
    let read_len = sector_size.min(max_len);

    if read_len == 0 {
        let fs = FileSystem::Unknown;
        audit.log(
            case_id,
            AuditEventType::FileSystemDetected {
                filesystem: fs.as_str().to_string(),
            },
        );
        return Ok(fs);
    }

    let boot_sector = container.read_at(base_offset, read_len)?;

    let mut fs = if boot_sector.len() >= 11 && &boot_sector[3..11] == b"NTFS    " {
        FileSystem::NTFS
    } else if boot_sector.len() >= 11 && &boot_sector[3..11] == b"EXFAT   " {
        FileSystem::ExFAT
    } else if boot_sector.len() >= 90 && &boot_sector[82..90] == b"FAT32   " {
        FileSystem::FAT32
    } else if boot_sector.len() >= 4 && &boot_sector[0..4] == b"XFSB" {
        FileSystem::XFS
    } else {
        FileSystem::Unknown
    };

    if fs == FileSystem::Unknown {
        let btrfs_super_offset = base_offset.saturating_add(0x10000);
        if btrfs_super_offset < container.size() {
            let probe_len = container.sector_size().max(4096);
            let available = container.size().saturating_sub(btrfs_super_offset);
            let read_len = probe_len.min(available);
            if read_len >= 0x48 {
                if let Ok(buf) = container.read_at(btrfs_super_offset, read_len) {
                    if buf.len() >= 0x48 && &buf[0x40..0x48] == b"_BHRfS_M" {
                        fs = FileSystem::Btrfs;
                    }
                }
            }
        }
    }

    audit.log(
        case_id,
        AuditEventType::FileSystemDetected {
            filesystem: fs.as_str().to_string(),
        },
    );

    Ok(fs)
}

/// Backwards-compatible wrapper: base offset = 0.
pub fn detect_filesystem<C: EvidenceContainerRO>(
    container: &C,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
) -> Result<FileSystem, ForensicError> {
    detect_filesystem_at(container, 0, case_id, audit)
}

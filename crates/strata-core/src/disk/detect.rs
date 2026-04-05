use crate::audit::event::AuditEventType;
use crate::audit::logger::AuditLogger;
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskLayout {
    Raw,
    Mbr,
    Gpt,
}

impl DiskLayout {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiskLayout::Raw => "RAW (no partition table)",
            DiskLayout::Mbr => "MBR",
            DiskLayout::Gpt => "GPT",
        }
    }
}

/// Detect disk layout using minimal reads.
/// Hardened behavior:
/// - If evidence is smaller than one sector, return RAW without emitting a read error.
/// - Never attempts to read beyond EOF.
/// - Logs DiskLayoutDetected.
pub fn detect_disk_layout<C: EvidenceContainerRO>(
    container: &C,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
) -> Result<DiskLayout, ForensicError> {
    let size = container.size();
    let sector_size = container.sector_size().max(512);

    // If the evidence is too small to contain an MBR/GPT header, treat as RAW.
    if size < 512 {
        let layout = DiskLayout::Raw;
        audit.log(
            case_id,
            AuditEventType::DiskLayoutDetected {
                layout: layout.as_str().to_string(),
            },
        );
        return Ok(layout);
    }

    // Safe read length: never beyond EOF
    let read_len = sector_size.min(size);
    let sector0 = container.read_at(0, read_len)?;

    // MBR signature is 0x55AA at bytes 510..511 (if we have them)
    let has_mbr_sig = sector0.len() >= 512
        && sector0[510] == 0x55
        && sector0[511] == 0xAA;

    // GPT protective MBR partition type 0xEE at partition entry 0 type byte:
    // MBR partition table starts at 0x1BE, type byte is at +4.
    let is_protective_mbr = sector0.len() >= 0x1BE + 16
        && sector0[0x1BE + 4] == 0xEE;

    let layout = if has_mbr_sig && is_protective_mbr {
        // To confirm GPT, we need to check LBA1 for "EFI PART".
        // LBA1 offset is 512 bytes (logical sector size for GPT header).
        // Read exactly 512 bytes, but never beyond EOF.
        if size >= 1024 {
            let hdr = container.read_at(512, 512)?;
            if hdr.len() >= 8 && &hdr[0..8] == b"EFI PART" {
                DiskLayout::Gpt
            } else {
                DiskLayout::Mbr
            }
        } else {
            // Not enough bytes for GPT header; safest classification is MBR-ish.
            DiskLayout::Mbr
        }
    } else if has_mbr_sig {
        DiskLayout::Mbr
    } else {
        DiskLayout::Raw
    };

    audit.log(
        case_id,
        AuditEventType::DiskLayoutDetected {
            layout: layout.as_str().to_string(),
        },
    );

    Ok(layout)
}

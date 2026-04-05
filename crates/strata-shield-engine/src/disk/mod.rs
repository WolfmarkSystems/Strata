use crate::audit::event::AuditEventType;
use crate::audit::logger::AuditLogger;
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum DiskLayout {
    Raw,
    MBR,
    GPT,
}

impl DiskLayout {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiskLayout::Raw => "RAW (no partition table)",
            DiskLayout::MBR => "MBR",
            DiskLayout::GPT => "GPT",
        }
    }
}

#[derive(Debug, Clone)]
pub enum VolumeKind {
    WholeDisk,
    MbrPartition,
    GptPartition,
}

impl VolumeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            VolumeKind::WholeDisk => "WholeDisk",
            VolumeKind::MbrPartition => "MBR Partition",
            VolumeKind::GptPartition => "GPT Partition",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VolumeInfo {
    pub index: u32,
    pub base_offset: u64,
    pub size: u64,
    pub kind: VolumeKind,
}

/// EOF-safe disk layout detection.
/// Policy-hardening compatible: only requests up to available bytes.
pub fn detect_disk_layout<C: EvidenceContainerRO>(
    container: &C,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
) -> Result<DiskLayout, ForensicError> {
    let ss = container.sector_size();
    let size = container.size();

    // Read only what exists (important for tiny images / test fixtures)
    let read_len = ss.min(size);
    if read_len == 0 {
        audit.log(
            case_id,
            AuditEventType::DiskLayoutDetected {
                layout: DiskLayout::Raw.as_str().to_string(),
            },
        );
        return Ok(DiskLayout::Raw);
    }

    let sector0 = container.read_at(0, read_len)?;

    // If we don't even have an MBR-sized buffer, it's RAW by definition.
    let layout = if sector0.len() < 512 {
        DiskLayout::Raw
    } else if sector0[510] == 0x55 && sector0[511] == 0xAA {
        // GPT protective MBR detection: partition type 0xEE in first partition entry
        let ptype = sector0[446 + 4];
        if ptype == 0xEE {
            DiskLayout::GPT
        } else {
            DiskLayout::MBR
        }
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

/// Phase-2: enumerate volumes.
/// Also EOF-safe: if evidence is too small to contain a valid partition table, returns WholeDisk.
pub fn list_volumes<C: EvidenceContainerRO>(
    container: &C,
    layout: &DiskLayout,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
) -> Result<Vec<VolumeInfo>, ForensicError> {
    let mut volumes = Vec::new();
    let disk_size = container.size();
    let ss = container.sector_size();

    // If the disk is too small to hold any partitioning structures, treat as whole disk.
    if disk_size < 512 {
        let v = VolumeInfo {
            index: 0,
            base_offset: 0,
            size: disk_size,
            kind: VolumeKind::WholeDisk,
        };
        audit.log(
            case_id,
            AuditEventType::VolumeDetected {
                index: v.index,
                base_offset: v.base_offset,
                size: v.size,
                kind: v.kind.as_str().to_string(),
            },
        );
        volumes.push(v);
        return Ok(volumes);
    }

    match layout {
        DiskLayout::Raw => {
            let v = VolumeInfo {
                index: 0,
                base_offset: 0,
                size: disk_size,
                kind: VolumeKind::WholeDisk,
            };
            audit.log(
                case_id,
                AuditEventType::VolumeDetected {
                    index: v.index,
                    base_offset: v.base_offset,
                    size: v.size,
                    kind: v.kind.as_str().to_string(),
                },
            );
            volumes.push(v);
        }

        DiskLayout::MBR => {
            let mbr = container.read_at(0, ss.min(disk_size))?;
            if mbr.len() < 512 {
                // shouldn't happen due to disk_size check, but keep it defensive
                let v = VolumeInfo {
                    index: 0,
                    base_offset: 0,
                    size: disk_size,
                    kind: VolumeKind::WholeDisk,
                };
                audit.log(
                    case_id,
                    AuditEventType::VolumeDetected {
                        index: v.index,
                        base_offset: v.base_offset,
                        size: v.size,
                        kind: v.kind.as_str().to_string(),
                    },
                );
                volumes.push(v);
                return Ok(volumes);
            }

            for i in 0..4 {
                let off = 446 + i * 16;
                let ent = &mbr[off..off + 16];

                let ptype = ent[4];
                if ptype == 0 {
                    continue;
                }

                let lba_start = u32::from_le_bytes([ent[8], ent[9], ent[10], ent[11]]) as u64;
                let sectors = u32::from_le_bytes([ent[12], ent[13], ent[14], ent[15]]) as u64;

                if sectors == 0 {
                    continue;
                }

                let base_offset = lba_start.saturating_mul(ss);
                let size = sectors.saturating_mul(ss);

                if base_offset >= disk_size {
                    continue;
                }

                let v = VolumeInfo {
                    index: volumes.len() as u32,
                    base_offset,
                    size: size.min(disk_size - base_offset),
                    kind: VolumeKind::MbrPartition,
                };

                audit.log(
                    case_id,
                    AuditEventType::VolumeDetected {
                        index: v.index,
                        base_offset: v.base_offset,
                        size: v.size,
                        kind: v.kind.as_str().to_string(),
                    },
                );

                volumes.push(v);
            }

            // If MBR had no valid partitions, fall back to whole disk.
            if volumes.is_empty() {
                let v = VolumeInfo {
                    index: 0,
                    base_offset: 0,
                    size: disk_size,
                    kind: VolumeKind::WholeDisk,
                };
                audit.log(
                    case_id,
                    AuditEventType::VolumeDetected {
                        index: v.index,
                        base_offset: v.base_offset,
                        size: v.size,
                        kind: v.kind.as_str().to_string(),
                    },
                );
                volumes.push(v);
            }
        }

        DiskLayout::GPT => {
            // GPT header at LBA 1 (offset = sector_size)
            if disk_size < ss.saturating_mul(2) {
                // not enough for LBA0 + LBA1
                let v = VolumeInfo {
                    index: 0,
                    base_offset: 0,
                    size: disk_size,
                    kind: VolumeKind::WholeDisk,
                };
                audit.log(
                    case_id,
                    AuditEventType::VolumeDetected {
                        index: v.index,
                        base_offset: v.base_offset,
                        size: v.size,
                        kind: v.kind.as_str().to_string(),
                    },
                );
                volumes.push(v);
                return Ok(volumes);
            }

            let header = container.read_at(ss, ss)?;
            if header.len() < 92 || &header[0..8] != b"EFI PART" {
                // GPT signature missing -> fall back
                let v = VolumeInfo {
                    index: 0,
                    base_offset: 0,
                    size: disk_size,
                    kind: VolumeKind::WholeDisk,
                };
                audit.log(
                    case_id,
                    AuditEventType::VolumeDetected {
                        index: v.index,
                        base_offset: v.base_offset,
                        size: v.size,
                        kind: v.kind.as_str().to_string(),
                    },
                );
                volumes.push(v);
                return Ok(volumes);
            }

            let entry_lba = u64::from_le_bytes(header[72..80].try_into().unwrap());
            let entry_count = u32::from_le_bytes(header[80..84].try_into().unwrap());
            let entry_size = u32::from_le_bytes(header[84..88].try_into().unwrap());

            if !(128..=4096).contains(&entry_size) || entry_count == 0 {
                let v = VolumeInfo {
                    index: 0,
                    base_offset: 0,
                    size: disk_size,
                    kind: VolumeKind::WholeDisk,
                };
                audit.log(
                    case_id,
                    AuditEventType::VolumeDetected {
                        index: v.index,
                        base_offset: v.base_offset,
                        size: v.size,
                        kind: v.kind.as_str().to_string(),
                    },
                );
                volumes.push(v);
                return Ok(volumes);
            }

            let table_off = entry_lba.saturating_mul(ss);
            let table_len = (entry_count as u64).saturating_mul(entry_size as u64);

            if table_off >= disk_size {
                let v = VolumeInfo {
                    index: 0,
                    base_offset: 0,
                    size: disk_size,
                    kind: VolumeKind::WholeDisk,
                };
                audit.log(
                    case_id,
                    AuditEventType::VolumeDetected {
                        index: v.index,
                        base_offset: v.base_offset,
                        size: v.size,
                        kind: v.kind.as_str().to_string(),
                    },
                );
                volumes.push(v);
                return Ok(volumes);
            }

            let readable = (disk_size - table_off).min(table_len);
            let table = container.read_at(table_off, readable)?;

            // If we didn't read enough to cover a single entry, fall back.
            if table.len() < entry_size as usize {
                let v = VolumeInfo {
                    index: 0,
                    base_offset: 0,
                    size: disk_size,
                    kind: VolumeKind::WholeDisk,
                };
                audit.log(
                    case_id,
                    AuditEventType::VolumeDetected {
                        index: v.index,
                        base_offset: v.base_offset,
                        size: v.size,
                        kind: v.kind.as_str().to_string(),
                    },
                );
                volumes.push(v);
                return Ok(volumes);
            }

            let max_entries = (table.len() as u64 / entry_size as u64) as u32;

            for i in 0..max_entries {
                let off = (i as usize) * (entry_size as usize);
                let ent = &table[off..off + (entry_size as usize)];

                if ent[0..16].iter().all(|&b| b == 0) {
                    continue;
                }

                let first_lba = u64::from_le_bytes(ent[32..40].try_into().unwrap());
                let last_lba = u64::from_le_bytes(ent[40..48].try_into().unwrap());

                if last_lba < first_lba {
                    continue;
                }

                let base_offset = first_lba.saturating_mul(ss);
                let size = (last_lba - first_lba + 1).saturating_mul(ss);

                if base_offset >= disk_size {
                    continue;
                }

                let v = VolumeInfo {
                    index: volumes.len() as u32,
                    base_offset,
                    size: size.min(disk_size - base_offset),
                    kind: VolumeKind::GptPartition,
                };

                audit.log(
                    case_id,
                    AuditEventType::VolumeDetected {
                        index: v.index,
                        base_offset: v.base_offset,
                        size: v.size,
                        kind: v.kind.as_str().to_string(),
                    },
                );

                volumes.push(v);
            }

            if volumes.is_empty() {
                let v = VolumeInfo {
                    index: 0,
                    base_offset: 0,
                    size: disk_size,
                    kind: VolumeKind::WholeDisk,
                };
                audit.log(
                    case_id,
                    AuditEventType::VolumeDetected {
                        index: v.index,
                        base_offset: v.base_offset,
                        size: v.size,
                        kind: v.kind.as_str().to_string(),
                    },
                );
                volumes.push(v);
            }
        }
    }

    Ok(volumes)
}

/// Compatibility helper (Phase-1). Keep it, but Phase-2 should use list_volumes().
pub fn detect_volume_base_offset<C: EvidenceContainerRO>(
    _container: &C,
    layout: &DiskLayout,
    _case_id: Uuid,
    _audit: Arc<AuditLogger>,
) -> Result<Option<u64>, ForensicError> {
    Ok(match layout {
        DiskLayout::Raw => Some(0),
        DiskLayout::MBR => Some(0),
        DiskLayout::GPT => Some(0),
    })
}

pub mod format;
pub mod multidisk;

pub use format::{
    detect_image_format, get_image_segments, ImageFormat, ImageFormatInfo, ImageSegment,
};
pub use multidisk::{detect_raid_config, read_from_disk_set, DiskSet, RaidType};

use crate::audit::event::AuditEventType;
use crate::audit::logger::AuditLogger;
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Fat32BootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fat_count: u8,
    pub total_sectors_16: u16,
    pub media_descriptor: u8,
    pub sectors_per_fat_16: u16,
    pub sectors_per_track: u16,
    pub heads: u16,
    pub hidden_sectors: u32,
    pub total_sectors_32: u32,
    pub sectors_per_fat_32: u32,
    pub flags: u16,
    pub fs_version: u16,
    pub root_cluster: u32,
    pub fsinfo_sector: u16,
    pub backup_boot_sector: u16,
    pub drive_number: u8,
    pub boot_signature: u8,
    pub volume_id: u32,
    pub volume_label: [u8; 11],
    pub fs_type: [u8; 8],
}

impl Fat32BootSector {
    pub fn total_sectors(&self) -> u64 {
        if self.total_sectors_32 != 0 {
            self.total_sectors_32 as u64
        } else {
            self.total_sectors_16 as u64
        }
    }

    pub fn cluster_size_bytes(&self) -> u64 {
        (self.bytes_per_sector as u64) * (self.sectors_per_cluster as u64)
    }

    pub fn fat_size_sectors(&self) -> u64 {
        if self.sectors_per_fat_32 != 0 {
            self.sectors_per_fat_32 as u64
        } else {
            self.sectors_per_fat_16 as u64
        }
    }

    pub fn first_data_sector(&self) -> u64 {
        (self.reserved_sectors as u64) + ((self.fat_count as u64) * self.fat_size_sectors())
    }

    pub fn data_sectors(&self) -> u64 {
        self.total_sectors()
            .saturating_sub(self.first_data_sector())
    }

    pub fn clusters(&self) -> u64 {
        self.data_sectors() / (self.sectors_per_cluster as u64)
    }

    pub fn volume_label_str(&self) -> String {
        let label = &self.volume_label;
        let end = label
            .iter()
            .position(|&b| b == 0x20 || b == 0)
            .unwrap_or(11);
        String::from_utf8_lossy(&label[..end]).to_string()
    }
}

#[derive(Debug)]
pub struct Fat32FastScanResult {
    pub boot: Fat32BootSector,
    pub fsinfo_sectors: Option<FsInfoSector>,
    pub volume_size_bytes: u64,
    pub free_clusters: Option<u32>,
    pub next_free_cluster: Option<u32>,
}

#[derive(Debug)]
pub struct FsInfoSector {
    pub free_clusters: u32,
    pub next_free_cluster: u32,
    pub signature: u32,
}

pub fn fat32_fast_scan<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
) -> Result<Fat32FastScanResult, ForensicError> {
    let sector_size = container.sector_size();
    if sector_size == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    let boot_sector = container.read_at(volume_base_offset, sector_size.min(container.size()))?;

    if boot_sector.len() < 90 {
        return Err(ForensicError::UnsupportedFilesystem);
    }

    let boot = Fat32BootSector {
        bytes_per_sector: u16::from_le_bytes([boot_sector[11], boot_sector[12]]),
        sectors_per_cluster: boot_sector[13],
        reserved_sectors: u16::from_le_bytes([boot_sector[14], boot_sector[15]]),
        fat_count: boot_sector[16],
        total_sectors_16: u16::from_le_bytes([boot_sector[19], boot_sector[20]]),
        media_descriptor: boot_sector[21],
        sectors_per_fat_16: u16::from_le_bytes([boot_sector[22], boot_sector[23]]),
        sectors_per_track: u16::from_le_bytes([boot_sector[24], boot_sector[25]]),
        heads: u16::from_le_bytes([boot_sector[26], boot_sector[27]]),
        hidden_sectors: u32::from_le_bytes([
            boot_sector[28],
            boot_sector[29],
            boot_sector[30],
            boot_sector[31],
        ]),
        total_sectors_32: u32::from_le_bytes([
            boot_sector[32],
            boot_sector[33],
            boot_sector[34],
            boot_sector[35],
        ]),
        sectors_per_fat_32: u32::from_le_bytes([
            boot_sector[36],
            boot_sector[37],
            boot_sector[38],
            boot_sector[39],
        ]),
        flags: u16::from_le_bytes([boot_sector[40], boot_sector[41]]),
        fs_version: u16::from_le_bytes([boot_sector[42], boot_sector[43]]),
        root_cluster: u32::from_le_bytes([
            boot_sector[44],
            boot_sector[45],
            boot_sector[46],
            boot_sector[47],
        ]),
        fsinfo_sector: u16::from_le_bytes([boot_sector[48], boot_sector[49]]),
        backup_boot_sector: u16::from_le_bytes([boot_sector[50], boot_sector[51]]),
        drive_number: boot_sector[64],
        boot_signature: boot_sector[66],
        volume_id: u32::from_le_bytes([
            boot_sector[67],
            boot_sector[68],
            boot_sector[69],
            boot_sector[70],
        ]),
        volume_label: boot_sector[71..82].try_into().unwrap(),
        fs_type: boot_sector[82..90].try_into().unwrap(),
    };

    let volume_size_bytes = boot.total_sectors() * (boot.bytes_per_sector as u64);

    let fsinfo = if boot.fsinfo_sector > 0 && boot.fsinfo_sector < 100 {
        let fsinfo_offset =
            volume_base_offset + (boot.fsinfo_sector as u64) * (boot.bytes_per_sector as u64);
        if fsinfo_offset + sector_size <= container.size() {
            match container.read_at(fsinfo_offset, sector_size) {
                Ok(fsinfo_data) if fsinfo_data.len() >= 484 => {
                    let sig = u32::from_le_bytes([
                        fsinfo_data[0],
                        fsinfo_data[1],
                        fsinfo_data[2],
                        fsinfo_data[3],
                    ]);
                    if sig == 0x41615252 {
                        Some(FsInfoSector {
                            signature: sig,
                            free_clusters: u32::from_le_bytes([
                                fsinfo_data[488],
                                fsinfo_data[489],
                                fsinfo_data[490],
                                fsinfo_data[491],
                            ]),
                            next_free_cluster: u32::from_le_bytes([
                                fsinfo_data[492],
                                fsinfo_data[493],
                                fsinfo_data[494],
                                fsinfo_data[495],
                            ]),
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            }
        } else {
            None
        }
    } else {
        None
    };

    let free_clusters = fsinfo.as_ref().map(|f| f.free_clusters);
    let next_free_cluster = fsinfo.as_ref().map(|f| f.next_free_cluster);

    audit.log(
        case_id,
        AuditEventType::FileSystemMetadata {
            filesystem: "FAT32".to_string(),
            label: boot.volume_label_str(),
            serial: Some(boot.volume_id),
            cluster_size: boot.cluster_size_bytes(),
            total_clusters: boot.clusters() as u32,
            free_clusters,
        },
    );

    Ok(Fat32FastScanResult {
        boot,
        fsinfo_sectors: fsinfo,
        volume_size_bytes,
        free_clusters,
        next_free_cluster,
    })
}

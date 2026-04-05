use crate::audit::event::AuditEventType;
use crate::audit::logger::AuditLogger;
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ExFatBootSector {
    pub jump_boot: [u8; 3],
    pub file_system_name: [u8; 8],
    pub must_be_zero: [u8; 53],
    pub partition_offset: u64,
    pub volume_length: u64,
    pub fat_offset: u32,
    pub fat_length: u32,
    pub cluster_heap_offset: u32,
    pub cluster_count: u32,
    pub first_cluster_of_root_directory: u32,
    pub volume_serial_number: u32,
    pub file_system_revision: u16,
    pub volume_flags: u16,
    pub bytes_per_cluster_shift: u8,
    pub number_of_fats: u8,
    pub drive_select: u8,
    pub percent_in_use: u8,
    pub boot_code: [u8; 390],
    pub boot_signature: u16,
}

impl ExFatBootSector {
    pub fn cluster_size(&self) -> u64 {
        1u64 << self.bytes_per_cluster_shift
    }

    pub fn bytes_per_sector(&self) -> u64 {
        0x10000u64.wrapping_shl(16) >> (32 - self.bytes_per_cluster_shift)
    }

    pub fn volume_label_str(&self) -> String {
        let label = &self.boot_code[0..11];
        let end = label.iter().position(|&b| b == 0x00).unwrap_or(11);
        String::from_utf8_lossy(&label[..end]).to_string()
    }
}

#[derive(Debug)]
pub struct ExFatFastScanResult {
    pub boot: ExFatBootSector,
    pub volume_size_bytes: u64,
    pub cluster_size_bytes: u64,
    pub total_clusters: u32,
}

pub fn exfat_fast_scan<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
) -> Result<ExFatFastScanResult, ForensicError> {
    let sector_size = container.sector_size();
    if sector_size == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    let boot_sector = container.read_at(volume_base_offset, sector_size.min(container.size()))?;

    if boot_sector.len() < 512 {
        return Err(ForensicError::UnsupportedFilesystem);
    }

    if &boot_sector[3..11] != b"EXFAT   " {
        return Err(ForensicError::UnsupportedFilesystem);
    }

    let boot = ExFatBootSector {
        jump_boot: boot_sector[0..3].try_into().unwrap(),
        file_system_name: boot_sector[3..11].try_into().unwrap(),
        must_be_zero: boot_sector[11..64].try_into().unwrap(),
        partition_offset: u64::from_le_bytes([
            boot_sector[64],
            boot_sector[65],
            boot_sector[66],
            boot_sector[67],
            boot_sector[68],
            boot_sector[69],
            boot_sector[70],
            boot_sector[71],
        ]),
        volume_length: u64::from_le_bytes([
            boot_sector[72],
            boot_sector[73],
            boot_sector[74],
            boot_sector[75],
            boot_sector[76],
            boot_sector[77],
            boot_sector[78],
            boot_sector[79],
        ]),
        fat_offset: u32::from_le_bytes([
            boot_sector[80],
            boot_sector[81],
            boot_sector[82],
            boot_sector[83],
        ]),
        fat_length: u32::from_le_bytes([
            boot_sector[84],
            boot_sector[85],
            boot_sector[86],
            boot_sector[87],
        ]),
        cluster_heap_offset: u32::from_le_bytes([
            boot_sector[88],
            boot_sector[89],
            boot_sector[90],
            boot_sector[91],
        ]),
        cluster_count: u32::from_le_bytes([
            boot_sector[92],
            boot_sector[93],
            boot_sector[94],
            boot_sector[95],
        ]),
        first_cluster_of_root_directory: u32::from_le_bytes([
            boot_sector[96],
            boot_sector[97],
            boot_sector[98],
            boot_sector[99],
        ]),
        volume_serial_number: u32::from_le_bytes([
            boot_sector[100],
            boot_sector[101],
            boot_sector[102],
            boot_sector[103],
        ]),
        file_system_revision: u16::from_le_bytes([boot_sector[104], boot_sector[105]]),
        volume_flags: u16::from_le_bytes([boot_sector[106], boot_sector[107]]),
        bytes_per_cluster_shift: boot_sector[108],
        number_of_fats: boot_sector[109],
        drive_select: boot_sector[110],
        percent_in_use: boot_sector[111],
        boot_code: boot_sector[112..502].try_into().unwrap(),
        boot_signature: u16::from_le_bytes([boot_sector[510], boot_sector[511]]),
    };

    let cluster_size_bytes = boot.cluster_size();
    let volume_size_bytes = boot.volume_length;
    let total_clusters = boot.cluster_count;

    audit.log(
        case_id,
        AuditEventType::FileSystemMetadata {
            filesystem: "exFAT".to_string(),
            label: boot.volume_label_str(),
            serial: Some(boot.volume_serial_number),
            cluster_size: cluster_size_bytes,
            total_clusters,
            free_clusters: None,
        },
    );

    Ok(ExFatFastScanResult {
        boot,
        volume_size_bytes,
        cluster_size_bytes,
        total_clusters,
    })
}

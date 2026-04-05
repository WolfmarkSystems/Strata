use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DiskLayout {
    Raw,
    MBR,
    GPT,
}

impl Default for DiskLayout {
    fn default() -> Self {
        Self::Raw
    }
}

pub fn detect_disk_layout_from_bytes(image: &[u8]) -> DiskLayout {
    if image.len() >= 1024 && &image[512..520] == b"EFI PART" {
        return DiskLayout::GPT;
    }

    if image.len() >= 512 && image[510] == 0x55 && image[511] == 0xAA {
        return DiskLayout::MBR;
    }

    DiskLayout::Raw
}

pub fn get_disk_layout_summary(path: &Path) -> DiskLayoutSummary {
    let Ok(bytes) = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) else {
        return DiskLayoutSummary::default();
    };
    parse_disk_layout_summary(&bytes)
}

pub fn parse_disk_layout_summary(image: &[u8]) -> DiskLayoutSummary {
    let layout = detect_disk_layout_from_bytes(image);
    let (mbr_partition_count, protective_mbr) = parse_mbr_partition_metadata(image);
    let gpt_partition_count = if layout == DiskLayout::GPT {
        parse_gpt_partition_count(image).unwrap_or(0)
    } else {
        0
    };

    DiskLayoutSummary {
        layout,
        mbr_partition_count,
        gpt_partition_count,
        protective_mbr,
    }
}

fn parse_mbr_partition_metadata(image: &[u8]) -> (u8, bool) {
    if image.len() < 512 {
        return (0, false);
    }

    let mut count = 0u8;
    let mut protective = false;
    let table_start = 446usize;

    for index in 0..4usize {
        let off = table_start + index * 16;
        if off + 16 > image.len() {
            break;
        }
        let ptype = image[off + 4];
        if ptype != 0 {
            count += 1;
        }
        if ptype == 0xEE {
            protective = true;
        }
    }

    (count, protective)
}

fn parse_gpt_partition_count(image: &[u8]) -> Option<u32> {
    if image.len() < 1024 || &image[512..520] != b"EFI PART" {
        return None;
    }

    let table_lba = le_u64_at(image, 512 + 72)?;
    let entry_count = le_u32_at(image, 512 + 80)?;
    let entry_size = le_u32_at(image, 512 + 84)?;
    if entry_count == 0 || entry_size < 16 {
        return Some(0);
    }

    let table_offset = (table_lba as usize).checked_mul(512)?;
    let entry_size = entry_size as usize;

    let mut used = 0u32;
    for index in 0..entry_count as usize {
        let off = table_offset.checked_add(index.checked_mul(entry_size)?)?;
        let end = off.checked_add(16)?;
        if end > image.len() {
            break;
        }
        if image[off..end].iter().any(|byte| *byte != 0) {
            used += 1;
        }
    }
    Some(used)
}

fn le_u32_at(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

fn le_u64_at(data: &[u8], off: usize) -> Option<u64> {
    if off + 8 > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ]))
}

#[derive(Debug, Clone, Default)]
pub struct DiskLayoutSummary {
    pub layout: DiskLayout,
    pub mbr_partition_count: u8,
    pub gpt_partition_count: u32,
    pub protective_mbr: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mbr_layout_and_partition_count() {
        let mut bytes = vec![0u8; 1024];
        bytes[510] = 0x55;
        bytes[511] = 0xAA;

        // First MBR entry type: NTFS (0x07)
        bytes[446 + 4] = 0x07;

        let summary = parse_disk_layout_summary(&bytes);
        assert_eq!(summary.layout, DiskLayout::MBR);
        assert_eq!(summary.mbr_partition_count, 1);
        assert_eq!(summary.gpt_partition_count, 0);
        assert!(!summary.protective_mbr);
    }

    #[test]
    fn parses_gpt_layout_and_used_partition_entries() {
        let mut bytes = vec![0u8; 512 * 34];
        bytes[510] = 0x55;
        bytes[511] = 0xAA;
        // Protective MBR partition type
        bytes[446 + 4] = 0xEE;

        // GPT signature at LBA1
        bytes[512..520].copy_from_slice(b"EFI PART");
        // Partition table LBA = 2
        bytes[512 + 72..512 + 80].copy_from_slice(&2u64.to_le_bytes());
        // Number of entries = 4
        bytes[512 + 80..512 + 84].copy_from_slice(&4u32.to_le_bytes());
        // Entry size = 128
        bytes[512 + 84..512 + 88].copy_from_slice(&128u32.to_le_bytes());

        // First entry has a non-zero partition type GUID
        bytes[1024..1040].copy_from_slice(&[1u8; 16]);

        let summary = parse_disk_layout_summary(&bytes);
        assert_eq!(summary.layout, DiskLayout::GPT);
        assert_eq!(summary.mbr_partition_count, 1);
        assert_eq!(summary.gpt_partition_count, 1);
        assert!(summary.protective_mbr);
    }
}

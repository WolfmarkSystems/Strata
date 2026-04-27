//! PARTITION-1 — MBR partition table walker.

use serde::{Deserialize, Serialize};

use crate::image::{EvidenceError, EvidenceImage, EvidenceResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MbrPartition {
    pub index: u8,
    pub active: bool,
    pub partition_type: u8,
    pub partition_type_name: String,
    pub start_lba: u64,
    pub sector_count: u64,
    pub offset_bytes: u64,
    pub size_bytes: u64,
}

pub fn read_mbr(image: &dyn EvidenceImage) -> EvidenceResult<Vec<MbrPartition>> {
    let sector_size = image.sector_size().max(1) as u64;
    let mut mbr = [0u8; 512];
    let n = image.read_at(0, &mut mbr)?;
    if n < 512 {
        return Err(EvidenceError::NoValidMbr);
    }
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        return Err(EvidenceError::NoValidMbr);
    }
    // If this is a GPT-protective MBR (single entry with type 0xEE),
    // return empty and let the caller use the GPT walker.
    let mut primary = Vec::new();
    for i in 0..4u8 {
        let entry_offset = 446 + (i as usize * 16);
        let entry = &mbr[entry_offset..entry_offset + 16];
        let ptype = entry[4];
        if ptype == 0 {
            continue;
        }
        let active = entry[0] == 0x80;
        let start_lba = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;
        let sectors = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as u64;
        primary.push(MbrPartition {
            index: i,
            active,
            partition_type: ptype,
            partition_type_name: partition_type_name(ptype).to_string(),
            start_lba,
            sector_count: sectors,
            offset_bytes: start_lba * sector_size,
            size_bytes: sectors * sector_size,
        });
    }
    // Protective MBR check: exactly one entry of type 0xEE spanning the
    // whole disk. Report as an empty list so the caller falls through
    // to GPT parsing.
    if primary.len() == 1 && primary[0].partition_type == 0xEE {
        return Ok(Vec::new());
    }

    // Walk extended partition chains (0x05 / 0x0F).
    let mut extended: Vec<MbrPartition> = Vec::new();
    for p in &primary {
        if matches!(p.partition_type, 0x05 | 0x0F | 0x85) {
            extended.extend(walk_ebr_chain(
                image,
                p.offset_bytes,
                p.offset_bytes,
                sector_size,
                p.index + 1,
            )?);
        }
    }
    let mut out = primary
        .into_iter()
        .filter(|p| !matches!(p.partition_type, 0x05 | 0x0F | 0x85))
        .collect::<Vec<_>>();
    out.extend(extended);
    Ok(out)
}

fn walk_ebr_chain(
    image: &dyn EvidenceImage,
    ebr_base: u64,
    current_ebr: u64,
    sector_size: u64,
    starting_index: u8,
) -> EvidenceResult<Vec<MbrPartition>> {
    let mut out = Vec::new();
    let mut cursor = current_ebr;
    let mut index = starting_index;
    loop {
        let mut sector = [0u8; 512];
        let n = image.read_at(cursor, &mut sector)?;
        if n < 512 || sector[510] != 0x55 || sector[511] != 0xAA {
            break;
        }
        // First entry: the logical partition
        let first = &sector[446..446 + 16];
        if first[4] != 0 {
            let start_lba = cursor / sector_size
                + u32::from_le_bytes([first[8], first[9], first[10], first[11]]) as u64;
            let sectors = u32::from_le_bytes([first[12], first[13], first[14], first[15]]) as u64;
            out.push(MbrPartition {
                index,
                active: first[0] == 0x80,
                partition_type: first[4],
                partition_type_name: partition_type_name(first[4]).to_string(),
                start_lba,
                sector_count: sectors,
                offset_bytes: start_lba * sector_size,
                size_bytes: sectors * sector_size,
            });
            index = index.saturating_add(1);
        }
        // Second entry: pointer to next EBR (relative to the extended
        // partition base).
        let second = &sector[462..462 + 16];
        if second[4] == 0 {
            break;
        }
        let next_rel = u32::from_le_bytes([second[8], second[9], second[10], second[11]]) as u64;
        if next_rel == 0 {
            break;
        }
        cursor = ebr_base + next_rel * sector_size;
    }
    Ok(out)
}

pub fn partition_type_name(t: u8) -> &'static str {
    match t {
        0x00 => "Empty",
        0x01 => "FAT12",
        0x04 | 0x06 | 0x0E => "FAT16",
        0x07 => "NTFS / exFAT",
        0x0B | 0x0C => "FAT32",
        0x0F | 0x05 | 0x85 => "Extended",
        0x27 => "Windows Recovery",
        0x42 => "LDM (Windows dynamic)",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x8E => "Linux LVM",
        0xA5 | 0xA6 | 0xA9 => "BSD",
        0xA8 => "Apple UFS",
        0xAB => "Apple boot",
        0xAF => "HFS / HFS+",
        0xEE => "GPT protective",
        0xEF => "EFI System Partition",
        0xFD => "Linux RAID",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::ImageMetadata;

    /// In-memory `EvidenceImage` backed by a byte vector, for tests.
    struct MemImage {
        bytes: Vec<u8>,
    }
    impl EvidenceImage for MemImage {
        fn size(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn format_name(&self) -> &'static str {
            "MemImage"
        }
        fn metadata(&self) -> ImageMetadata {
            ImageMetadata::minimal("MemImage", self.bytes.len() as u64, 512)
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> EvidenceResult<usize> {
            let o = offset as usize;
            if o >= self.bytes.len() {
                return Ok(0);
            }
            let n = (self.bytes.len() - o).min(buf.len());
            buf[..n].copy_from_slice(&self.bytes[o..o + n]);
            Ok(n)
        }
    }

    fn make_mbr(entries: &[(u8, u8, u32, u32)]) -> Vec<u8> {
        let mut mbr = vec![0u8; 512];
        for (i, (flag, ptype, start_lba, sectors)) in entries.iter().enumerate() {
            let o = 446 + i * 16;
            mbr[o] = *flag;
            mbr[o + 4] = *ptype;
            mbr[o + 8..o + 12].copy_from_slice(&start_lba.to_le_bytes());
            mbr[o + 12..o + 16].copy_from_slice(&sectors.to_le_bytes());
        }
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        mbr
    }

    #[test]
    fn parses_mbr_with_one_primary_partition() {
        let bytes = make_mbr(&[(0x80, 0x07, 2048, 100_000)]);
        let img = MemImage { bytes };
        let parts = read_mbr(&img).expect("mbr");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].partition_type, 0x07);
        assert_eq!(parts[0].offset_bytes, 2048 * 512);
        assert!(parts[0].active);
    }

    #[test]
    fn parses_mbr_with_four_primary_partitions() {
        let bytes = make_mbr(&[
            (0, 0x83, 2048, 100_000),
            (0, 0x82, 102_048, 1000),
            (0, 0x0B, 103_048, 200_000),
            (0, 0x07, 303_048, 200_000),
        ]);
        let img = MemImage { bytes };
        let parts = read_mbr(&img).expect("mbr");
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0].partition_type_name, "Linux");
        assert_eq!(parts[2].partition_type_name, "FAT32");
    }

    #[test]
    fn rejects_invalid_signature() {
        let mut bytes = vec![0u8; 512];
        bytes[510] = 0x00;
        bytes[511] = 0x00;
        let img = MemImage { bytes };
        assert!(matches!(read_mbr(&img), Err(EvidenceError::NoValidMbr)));
    }

    #[test]
    fn gpt_protective_mbr_returns_empty() {
        let bytes = make_mbr(&[(0, 0xEE, 1, 0xFFFF_FFFF)]);
        let img = MemImage { bytes };
        let parts = read_mbr(&img).expect("mbr");
        assert!(parts.is_empty());
    }

    #[test]
    fn extended_partition_chain_walks() {
        // Disk layout:
        //   LBA 0: MBR with one primary (NTFS) + one extended at LBA 10_000
        //   LBA 10_000: EBR #1 — logical Linux partition at +2048, + pointer to EBR #2 @ relative 20_000
        //   LBA 30_000: EBR #2 — logical swap partition at +2048, no next pointer
        let sector_size = 512u64;
        let mut disk = vec![0u8; (40_000 * sector_size) as usize];
        let primary = make_mbr(&[(0, 0x07, 2048, 8_000), (0, 0x05, 10_000, 30_000)]);
        disk[..512].copy_from_slice(&primary);

        let ebr1_offset = 10_000 * sector_size as usize;
        let ebr1 = make_mbr(&[
            (0, 0x83, 2048, 5_000),    // logical partition
            (0, 0x05, 20_000, 10_000), // pointer to next EBR (relative)
        ]);
        disk[ebr1_offset..ebr1_offset + 512].copy_from_slice(&ebr1);

        let ebr2_offset = (10_000 + 20_000) * sector_size as usize;
        let ebr2 = make_mbr(&[(0, 0x82, 2048, 1_000)]);
        disk[ebr2_offset..ebr2_offset + 512].copy_from_slice(&ebr2);

        let img = MemImage { bytes: disk };
        let parts = read_mbr(&img).expect("mbr");
        assert_eq!(parts.len(), 3, "primary + 2 logicals; got {:?}", parts);
        assert!(parts.iter().any(|p| p.partition_type == 0x83));
        assert!(parts.iter().any(|p| p.partition_type == 0x82));
    }

    #[test]
    fn type_name_lookup_covers_common_cases() {
        assert_eq!(partition_type_name(0x07), "NTFS / exFAT");
        assert_eq!(partition_type_name(0x83), "Linux");
        assert_eq!(partition_type_name(0xAF), "HFS / HFS+");
    }
}

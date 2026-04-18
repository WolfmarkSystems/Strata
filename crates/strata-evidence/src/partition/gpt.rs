//! PARTITION-2 — GPT partition table walker.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::image::{EvidenceError, EvidenceImage, EvidenceResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GptPartition {
    pub index: u32,
    pub partition_type_guid: Uuid,
    pub partition_type_name: String,
    pub unique_guid: Uuid,
    pub start_lba: u64,
    pub end_lba: u64,
    pub attributes: u64,
    pub name: String,
    pub offset_bytes: u64,
    pub size_bytes: u64,
}

pub fn read_gpt(image: &dyn EvidenceImage) -> EvidenceResult<Vec<GptPartition>> {
    let sector_size = image.sector_size().max(512) as u64;
    // Header at LBA 1
    let mut header = vec![0u8; sector_size as usize];
    let n = image.read_at(sector_size, &mut header)?;
    if n < 92 || &header[..8] != b"EFI PART" {
        return Err(EvidenceError::NoValidGpt);
    }
    let partition_entry_lba = u64::from_le_bytes([
        header[72], header[73], header[74], header[75], header[76], header[77], header[78],
        header[79],
    ]);
    let partition_count = u32::from_le_bytes([header[80], header[81], header[82], header[83]]);
    let partition_entry_size =
        u32::from_le_bytes([header[84], header[85], header[86], header[87]]);
    if partition_entry_size == 0
        || partition_count == 0
        || partition_entry_size > 8192
        || partition_count > 4096
    {
        return Err(EvidenceError::InvalidHeader {
            format: "GPT",
            reason: "implausible partition entry layout".into(),
        });
    }

    let mut out: Vec<GptPartition> = Vec::new();
    let mut entry_buf = vec![0u8; partition_entry_size as usize];
    for i in 0..partition_count {
        let off = partition_entry_lba * sector_size + (i as u64 * partition_entry_size as u64);
        let got = image.read_at(off, &mut entry_buf)?;
        if got < partition_entry_size as usize {
            break;
        }
        if entry_buf[..16].iter().all(|b| *b == 0) {
            continue;
        }
        let type_guid = guid_from_le_bytes(&entry_buf[..16]);
        let unique_guid = guid_from_le_bytes(&entry_buf[16..32]);
        let start_lba = u64::from_le_bytes([
            entry_buf[32], entry_buf[33], entry_buf[34], entry_buf[35], entry_buf[36],
            entry_buf[37], entry_buf[38], entry_buf[39],
        ]);
        let end_lba = u64::from_le_bytes([
            entry_buf[40], entry_buf[41], entry_buf[42], entry_buf[43], entry_buf[44],
            entry_buf[45], entry_buf[46], entry_buf[47],
        ]);
        let attributes = u64::from_le_bytes([
            entry_buf[48], entry_buf[49], entry_buf[50], entry_buf[51], entry_buf[52],
            entry_buf[53], entry_buf[54], entry_buf[55],
        ]);
        let name = decode_utf16_null_terminated(&entry_buf[56..128.min(entry_buf.len())]);
        let size_bytes = if end_lba >= start_lba {
            (end_lba - start_lba + 1) * sector_size
        } else {
            0
        };
        out.push(GptPartition {
            index: i,
            partition_type_guid: type_guid,
            partition_type_name: gpt_type_name(&type_guid).to_string(),
            unique_guid,
            start_lba,
            end_lba,
            attributes,
            name,
            offset_bytes: start_lba * sector_size,
            size_bytes,
        });
    }
    Ok(out)
}

fn guid_from_le_bytes(bytes: &[u8]) -> Uuid {
    // GPT stores the first three fields little-endian, last two big-endian.
    if bytes.len() < 16 {
        return Uuid::nil();
    }
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let mut d4 = [0u8; 8];
    d4.copy_from_slice(&bytes[8..16]);
    Uuid::from_fields(d1, d2, d3, &d4)
}

fn decode_utf16_null_terminated(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

pub fn gpt_type_name(guid: &Uuid) -> &'static str {
    let s = guid.to_string().to_ascii_lowercase();
    match s.as_str() {
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "EFI System Partition",
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => "Microsoft Basic Data",
        "e3c9e316-0b5c-4db8-817d-f92df00215ae" => "Microsoft Reserved",
        "de94bba4-06d1-4d40-a16a-bfd50179d6ac" => "Windows Recovery",
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => "Linux filesystem",
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => "Linux swap",
        "e6d6d379-f507-44c2-a23c-238f2a3df928" => "Linux LVM",
        "7c3457ef-0000-11aa-aa11-00306543ecac" => "Apple APFS",
        "48465300-0000-11aa-aa11-00306543ecac" => "Apple HFS+",
        "426f6f74-0000-11aa-aa11-00306543ecac" => "Apple Boot",
        "52637672-7900-11aa-aa11-00306543ecac" => "Apple Recovery",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::ImageMetadata;

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

    fn make_gpt_with_one_partition(type_guid: [u8; 16]) -> Vec<u8> {
        let sector_size = 512usize;
        // Big enough for protective MBR + GPT header + partition entries.
        let mut disk = vec![0u8; sector_size * 100];
        // LBA 1: GPT header
        let hdr = &mut disk[sector_size..sector_size + 128];
        hdr[0..8].copy_from_slice(b"EFI PART");
        // partition_entry_lba = 2
        hdr[72..80].copy_from_slice(&2u64.to_le_bytes());
        // partition_count = 1, partition_entry_size = 128
        hdr[80..84].copy_from_slice(&1u32.to_le_bytes());
        hdr[84..88].copy_from_slice(&128u32.to_le_bytes());
        // Partition entry at LBA 2
        let entry_off = sector_size * 2;
        let entry = &mut disk[entry_off..entry_off + 128];
        entry[..16].copy_from_slice(&type_guid);
        // unique GUID — arbitrary
        entry[16..32].copy_from_slice(&[1u8; 16]);
        // start_lba = 34, end_lba = 99
        entry[32..40].copy_from_slice(&34u64.to_le_bytes());
        entry[40..48].copy_from_slice(&99u64.to_le_bytes());
        // UTF-16LE name "Main"
        let name_bytes: Vec<u8> = "Main"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        entry[56..56 + name_bytes.len()].copy_from_slice(&name_bytes);
        disk
    }

    #[test]
    fn parses_gpt_with_microsoft_basic_data_partition() {
        // Microsoft Basic Data type GUID in little-endian layout:
        // EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
        let mut guid = [0u8; 16];
        guid[0..4].copy_from_slice(&0xEBD0_A0A2u32.to_le_bytes());
        guid[4..6].copy_from_slice(&0xB9E5u16.to_le_bytes());
        guid[6..8].copy_from_slice(&0x4433u16.to_le_bytes());
        guid[8..16].copy_from_slice(&[0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7]);
        let disk = make_gpt_with_one_partition(guid);
        let img = MemImage { bytes: disk };
        let parts = read_gpt(&img).expect("gpt");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].partition_type_name, "Microsoft Basic Data");
        assert_eq!(parts[0].name, "Main");
    }

    #[test]
    fn rejects_invalid_gpt_signature() {
        let mut disk = vec![0u8; 4096];
        disk[512..520].copy_from_slice(b"NOTGPT!!");
        let img = MemImage { bytes: disk };
        assert!(matches!(read_gpt(&img), Err(EvidenceError::NoValidGpt)));
    }

    #[test]
    fn utf16_decoder_stops_at_null() {
        let mut bytes = Vec::new();
        for u in "Hello".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&[0xFF; 6]);
        assert_eq!(decode_utf16_null_terminated(&bytes), "Hello");
    }

    #[test]
    fn guid_parser_round_trips_known_uuid() {
        // APFS type: 7C3457EF-0000-11AA-AA11-00306543ECAC
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&0x7C34_57EFu32.to_le_bytes());
        b[4..6].copy_from_slice(&0x0000u16.to_le_bytes());
        b[6..8].copy_from_slice(&0x11AAu16.to_le_bytes());
        b[8..16].copy_from_slice(&[0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC]);
        let u = guid_from_le_bytes(&b);
        assert_eq!(u.to_string(), "7c3457ef-0000-11aa-aa11-00306543ecac");
        assert_eq!(gpt_type_name(&u), "Apple APFS");
    }

    #[test]
    fn empty_entries_are_skipped() {
        let disk = make_gpt_with_one_partition([0u8; 16]);
        let img = MemImage { bytes: disk };
        let parts = read_gpt(&img).expect("gpt");
        assert!(parts.is_empty());
    }
}

//! Volume Shadow Copy (VSS) enumeration and catalog parsing.
//!
//! The Windows Volume Shadow Copy Service writes its on-disk structures inside
//! NTFS volumes.  The layout (documented by libvshadow / Joachim Metz) is:
//!
//! ```text
//! Volume + 0x1E00   VSS Volume Header (512 bytes)
//!                   ├─ 16-byte identifier GUID
//!                   ├─ u32 version
//!                   ├─ u64 catalog_offset (relative to volume start)
//!                   └─ u64 maximum_size
//!
//! Catalog chain     0x4000-byte blocks, linked list
//!                   ├─ 16-byte identifier GUID (same as header)
//!                   ├─ u32 block_type (0x02 = catalog)
//!                   ├─ u64 next_block_offset
//!                   └─ 128-byte entries starting at offset 0x80
//!                       ├─ u64 entry_type (0x03 = snapshot descriptor)
//!                       ├─ 16-byte store_guid (0x08)
//!                       ├─ 16-byte snapshot_id (0x28 or 0x38)
//!                       └─ FILETIME creation_time (0x30 or 0x48)
//! ```
//!
//! This module:
//! 1. Detects the VSS volume header on an NTFS partition.
//! 2. Walks the catalog chain to enumerate every shadow copy snapshot.
//! 3. Returns `VssSnapshot` structs that the VFS layer converts into
//!    selectable `VolumeInfo` entries so examiners can choose a snapshot.
//!
//! Forensic value:
//! Shadow copies contain prior versions of every file on the volume.
//! Attackers routinely delete them (`vssadmin delete shadows /all /quiet`),
//! so finding *intact* snapshots is high-value evidence, and finding them
//! *absent* is evidence of anti-forensics (MITRE T1490).

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;
use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────────────────
// On-disk constants
// ────────────────────────────────────────────────────────────────────────────

/// Byte offset from the start of an NTFS volume where the VSS volume header
/// lives. This is the fixed position defined by Microsoft.
const VSS_HEADER_OFFSET: u64 = 0x1E00;

/// 16-byte identifier GUID that appears at the start of both the VSS volume
/// header and every catalog block. This is GUID
/// `{6B870838-76B1-4B48-B715-52131953003E}` stored in Windows mixed-endian
/// (Data1 LE, Data2 LE, Data3 LE, Data4 BE).
const VSS_IDENTIFIER: [u8; 16] = [
    0x6B, 0x87, 0x08, 0x38, // Data1 LE
    0x76, 0xB1, // Data2 LE
    0x4B, 0x48, // Data3 LE
    0xB7, 0x15, 0x52, 0x13, 0x19, 0x53, 0x00, 0x3E, // Data4 BE
];

/// Catalog block size (16 KiB).
const CATALOG_BLOCK_SIZE: usize = 0x4000;

/// Maximum number of catalog blocks we follow (prevents infinite loops on
/// corrupt data).
const MAX_CATALOG_BLOCKS: usize = 256;

/// Maximum number of snapshots we enumerate (sanity limit).
const MAX_SNAPSHOTS: usize = 512;

/// Size of a single catalog entry in bytes.
const CATALOG_ENTRY_SIZE: usize = 128;

/// Catalog entries start at this offset within a catalog block.
const CATALOG_ENTRIES_OFFSET: usize = 0x80;

/// Entry type values.
const ENTRY_TYPE_EMPTY: u64 = 0x00;
const ENTRY_TYPE_VOLUME: u64 = 0x02;
const ENTRY_TYPE_SNAPSHOT: u64 = 0x03;

/// FILETIME epoch offset: 100-nanosecond intervals between
/// 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

// ────────────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────────────

/// A single VSS snapshot discovered on an NTFS volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssSnapshot {
    /// Snapshot identifier GUID (unique per snapshot).
    pub snapshot_id: String,
    /// Snapshot set GUID (groups snapshots taken at the same time across
    /// multiple volumes).
    pub snapshot_set_id: String,
    /// Creation time as Unix epoch seconds.
    pub creation_time: Option<i64>,
    /// Byte offset of the snapshot's data store within the NTFS volume.
    pub store_offset: u64,
    /// Sequential index among all snapshots discovered on this volume
    /// (0-based, in catalog order which is typically newest-first).
    pub index: usize,
}

/// The VSS volume header located at `VSS_HEADER_OFFSET` within an NTFS
/// volume.
#[derive(Debug, Clone)]
pub struct VssVolumeHeader {
    /// VSS format version (usually 0x01).
    pub version: u32,
    /// Absolute byte offset of the first catalog block (relative to the
    /// start of the NTFS volume, NOT the disk).
    pub catalog_offset: u64,
    /// Maximum size reserved for VSS data on this volume.
    pub max_size: u64,
}

/// Legacy types retained for backward compatibility with existing callers.
#[derive(Debug, Clone)]
pub enum ShadowCopyType {
    VSS,
    VSSProvider,
    ShadowVolume,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ShadowCopyInfo {
    pub copy_type: ShadowCopyType,
    pub offset: u64,
    pub size: Option<u64>,
    pub description: String,
}

// ────────────────────────────────────────────────────────────────────────────
// Core API — snapshot enumeration
// ────────────────────────────────────────────────────────────────────────────

/// Enumerate all VSS snapshots on an NTFS volume.
///
/// `volume_base_offset` is the byte offset of the NTFS volume within the
/// container (0 for a bare volume, partition start for a multi-partition
/// disk image).
///
/// Returns an empty vec if no VSS structures are present.
pub fn enumerate_vss_snapshots<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
) -> Result<Vec<VssSnapshot>, ForensicError> {
    let header = match read_vss_header(container, volume_base_offset)? {
        Some(h) => h,
        None => return Ok(Vec::new()),
    };

    let mut snapshots = Vec::new();
    let mut catalog_offset = header.catalog_offset;
    let mut blocks_visited = 0;

    while catalog_offset != 0
        && blocks_visited < MAX_CATALOG_BLOCKS
        && snapshots.len() < MAX_SNAPSHOTS
    {
        let absolute_offset = volume_base_offset + catalog_offset;

        // Read the full catalog block.
        let block_data = match container.read_at(absolute_offset, CATALOG_BLOCK_SIZE as u64) {
            Ok(d) if d.len() >= CATALOG_BLOCK_SIZE => d,
            _ => break,
        };

        // Validate the block starts with the VSS identifier.
        if block_data[..16] != VSS_IDENTIFIER {
            break;
        }

        // Block type at offset 0x10 (u32 LE). 0x02 = catalog block.
        let block_type = read_u32_le(&block_data, 0x10);
        if block_type != 0x02 {
            break;
        }

        // Parse entries within this catalog block.
        let mut entry_offset = CATALOG_ENTRIES_OFFSET;
        while entry_offset + CATALOG_ENTRY_SIZE <= CATALOG_BLOCK_SIZE
            && snapshots.len() < MAX_SNAPSHOTS
        {
            let entry = &block_data[entry_offset..entry_offset + CATALOG_ENTRY_SIZE];
            let entry_type = read_u64_le(entry, 0x00);

            match entry_type {
                ENTRY_TYPE_SNAPSHOT => {
                    let snapshot = parse_snapshot_entry(entry, snapshots.len());
                    snapshots.push(snapshot);
                }
                ENTRY_TYPE_EMPTY => {
                    // End of entries in this block.
                    break;
                }
                ENTRY_TYPE_VOLUME => {
                    // Volume descriptor — skip, continue to next entry.
                }
                _ => {
                    // Unknown entry type — skip.
                }
            }

            entry_offset += CATALOG_ENTRY_SIZE;
        }

        // Follow the chain to the next catalog block (u64 at offset 0x2C).
        let next_offset = read_u64_le(&block_data, 0x2C);
        if next_offset == 0 || next_offset == catalog_offset {
            break;
        }
        catalog_offset = next_offset;
        blocks_visited += 1;
    }

    Ok(snapshots)
}

/// Read and validate the VSS volume header.
///
/// Returns `None` if no VSS header is present (normal for volumes without
/// shadow copies). Returns an error only on I/O failure.
pub fn read_vss_header<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
) -> Result<Option<VssVolumeHeader>, ForensicError> {
    let header_offset = volume_base_offset + VSS_HEADER_OFFSET;

    // We need at least the first 0x44 bytes of the header.
    if header_offset + 0x44 > container.size() {
        return Ok(None);
    }

    let data = container.read_at(header_offset, 0x44)?;
    if data.len() < 0x44 {
        return Ok(None);
    }

    // Check for the VSS identifier GUID.
    if data[..16] != VSS_IDENTIFIER {
        return Ok(None);
    }

    let version = read_u32_le(&data, 0x10);
    let catalog_offset = read_u64_le(&data, 0x34);
    let max_size = read_u64_le(&data, 0x3C);

    // Sanity check: catalog offset must be positive and within the volume.
    if catalog_offset == 0 {
        return Ok(None);
    }

    Ok(Some(VssVolumeHeader {
        version,
        catalog_offset,
        max_size,
    }))
}

// ────────────────────────────────────────────────────────────────────────────
// Legacy API — retained for backward compatibility
// ────────────────────────────────────────────────────────────────────────────

/// Detect shadow copies on an NTFS volume (legacy API).
///
/// Callers should prefer `enumerate_vss_snapshots()` for richer data.
pub fn detect_shadow_copies<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
    _volume_size: u64,
) -> Result<Vec<ShadowCopyInfo>, ForensicError> {
    let mut results = Vec::new();

    if let Some(header) = read_vss_header(container, volume_base_offset)? {
        results.push(ShadowCopyInfo {
            copy_type: ShadowCopyType::VSS,
            offset: volume_base_offset + VSS_HEADER_OFFSET,
            size: Some(header.max_size),
            description: format!(
                "VSS volume header (v{}, catalog at 0x{:X}, max {})",
                header.version, header.catalog_offset, header.max_size
            ),
        });

        let snapshots = enumerate_vss_snapshots(container, volume_base_offset)?;
        for snap in &snapshots {
            results.push(ShadowCopyInfo {
                copy_type: ShadowCopyType::VSS,
                offset: volume_base_offset + snap.store_offset,
                size: None,
                description: format!(
                    "VSS snapshot {} (created: {})",
                    snap.snapshot_id,
                    snap.creation_time
                        .map(|t| format!("epoch {}", t))
                        .unwrap_or_else(|| "unknown".into()),
                ),
            });
        }
    }

    Ok(results)
}

/// List byte offsets of shadow volume headers (legacy API).
pub fn list_shadow_volume_offsets<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
    _max_shadows: u32,
) -> Result<Vec<u64>, ForensicError> {
    let snapshots = enumerate_vss_snapshots(container, volume_base_offset)?;
    Ok(snapshots
        .iter()
        .map(|s| volume_base_offset + s.store_offset)
        .collect())
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

fn parse_snapshot_entry(entry: &[u8], index: usize) -> VssSnapshot {
    // The catalog entry for a snapshot (type 0x03) has the following layout:
    //   0x00: u64  entry_type (0x03)
    //   0x08: u64  store_data_block_offset
    //   0x10: 16b  store_guid (not the snapshot ID)
    //   0x20: 16b  snapshot_set_id (groups multi-volume snapshots)
    //   0x30: 8b   creation_time (FILETIME)
    //   0x38: 16b  snapshot_id (the unique GUID we label)
    //
    // Some VSS versions swap snapshot_id and snapshot_set_id positions.
    // We try both common layouts and pick the one with a valid FILETIME.

    let store_offset = read_u64_le(entry, 0x08);

    // Layout A (Windows 7/8/10): creation_time at 0x30, snapshot_id at 0x38
    let ft_a = read_u64_le(entry, 0x30);
    let time_a = filetime_to_unix(ft_a);

    // Layout B (some Vista builds): creation_time at 0x48, snapshot_id at 0x28
    let ft_b = read_u64_le(entry, 0x48);
    let time_b = filetime_to_unix(ft_b);

    let (creation_time, snapshot_id_offset, snapshot_set_id_offset) = if time_a.is_some() {
        (time_a, 0x38usize, 0x20usize)
    } else if time_b.is_some() {
        (time_b, 0x28usize, 0x10usize)
    } else {
        // Neither looks like a valid FILETIME — use layout A offsets and
        // let the timestamp be None.
        (None, 0x38usize, 0x20usize)
    };

    let snapshot_id = if snapshot_id_offset + 16 <= entry.len() {
        format_guid(&entry[snapshot_id_offset..snapshot_id_offset + 16])
    } else {
        "unknown".to_string()
    };

    let snapshot_set_id = if snapshot_set_id_offset + 16 <= entry.len() {
        format_guid(&entry[snapshot_set_id_offset..snapshot_set_id_offset + 16])
    } else {
        "unknown".to_string()
    };

    VssSnapshot {
        snapshot_id,
        snapshot_set_id,
        creation_time,
        store_offset,
        index,
    }
}

fn filetime_to_unix(ft: u64) -> Option<i64> {
    if ft <= FILETIME_UNIX_EPOCH || ft == 0 {
        return None;
    }
    Some(((ft - FILETIME_UNIX_EPOCH) / 10_000_000) as i64)
}

fn format_guid(data: &[u8]) -> String {
    if data.len() < 16 {
        return "invalid-guid".to_string();
    }
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        u16::from_le_bytes([data[4], data[5]]),
        u16::from_le_bytes([data[6], data[7]]),
        data[8],
        data[9],
        data[10],
        data[11],
        data[12],
        data[13],
        data[14],
        data[15],
    )
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// In-memory evidence container for testing. Stores a flat byte buffer
    /// and serves reads from it.
    struct MemContainer {
        data: Vec<u8>,
    }

    impl MemContainer {
        fn new(size: usize) -> Self {
            Self {
                data: vec![0u8; size],
            }
        }

        fn write_bytes(&mut self, offset: usize, bytes: &[u8]) {
            let end = offset + bytes.len();
            if end <= self.data.len() {
                self.data[offset..end].copy_from_slice(bytes);
            }
        }

        fn write_u32_le(&mut self, offset: usize, val: u32) {
            self.write_bytes(offset, &val.to_le_bytes());
        }

        fn write_u64_le(&mut self, offset: usize, val: u64) {
            self.write_bytes(offset, &val.to_le_bytes());
        }
    }

    impl EvidenceContainerRO for MemContainer {
        fn description(&self) -> &str {
            "test"
        }
        fn source_path(&self) -> &Path {
            Path::new("/test")
        }
        fn size(&self) -> u64 {
            self.data.len() as u64
        }
        fn sector_size(&self) -> u64 {
            512
        }
        fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
            let start = offset as usize;
            let end = start + buf.len();
            if end > self.data.len() {
                return Err(ForensicError::OutOfRange(format!(
                    "read at {} len {} exceeds {}",
                    start,
                    buf.len(),
                    self.data.len()
                )));
            }
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }
    }

    /// Build a minimal but structurally valid VSS image in memory.
    ///
    /// Layout:
    ///   - Offset 0x0000: NTFS VBR stub (not parsed, just filler)
    ///   - Offset 0x1E00: VSS Volume Header
    ///   - Offset 0x4000: Catalog block with 2 snapshot entries
    fn build_test_vss_image() -> MemContainer {
        let size = 0x10000; // 64 KB
        let mut c = MemContainer::new(size);

        // ── VSS Volume Header at 0x1E00 ──
        let hdr = 0x1E00;
        c.write_bytes(hdr, &VSS_IDENTIFIER); // identifier
        c.write_u32_le(hdr + 0x10, 0x01); // version
        c.write_u64_le(hdr + 0x34, 0x4000); // catalog_offset
        c.write_u64_le(hdr + 0x3C, 0x1000_0000); // max_size

        // ── Catalog block at 0x4000 ──
        let cat = 0x4000;
        c.write_bytes(cat, &VSS_IDENTIFIER); // block identifier
        c.write_u32_le(cat + 0x10, 0x02); // block_type = catalog
        c.write_u64_le(cat + 0x2C, 0x00); // next_block = 0 (end)

        // ── Entry 0 (volume descriptor, type 0x02) at cat + 0x80 ──
        let e0 = cat + CATALOG_ENTRIES_OFFSET;
        c.write_u64_le(e0, ENTRY_TYPE_VOLUME);

        // ── Entry 1 (snapshot, type 0x03) at cat + 0x100 ──
        let e1 = e0 + CATALOG_ENTRY_SIZE;
        c.write_u64_le(e1, ENTRY_TYPE_SNAPSHOT);
        c.write_u64_le(e1 + 0x08, 0x8000); // store_offset

        // Snapshot set GUID at 0x20
        let guid1_set: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x00, 0x11,
        ];
        c.write_bytes(e1 + 0x20, &guid1_set);

        // Creation FILETIME at 0x30 (represents ~2024-01-15)
        // 133_496_352_000_000_000 (0x01DA_6B40_9D48_0000)
        let ft1: u64 = 133_496_352_000_000_000;
        c.write_u64_le(e1 + 0x30, ft1);

        // Snapshot GUID at 0x38
        let guid1_snap: [u8; 16] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xAA, 0xBB,
        ];
        c.write_bytes(e1 + 0x38, &guid1_snap);

        // ── Entry 2 (snapshot, type 0x03) at cat + 0x180 ──
        let e2 = e1 + CATALOG_ENTRY_SIZE;
        c.write_u64_le(e2, ENTRY_TYPE_SNAPSHOT);
        c.write_u64_le(e2 + 0x08, 0xC000); // store_offset

        let guid2_set: [u8; 16] = [
            0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
            0xA7, 0xA8,
        ];
        c.write_bytes(e2 + 0x20, &guid2_set);

        // Creation FILETIME at 0x30 (~2024-02-01)
        let ft2: u64 = 133_510_944_000_000_000;
        c.write_u64_le(e2 + 0x30, ft2);

        let guid2_snap: [u8; 16] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        c.write_bytes(e2 + 0x38, &guid2_snap);

        c
    }

    #[test]
    fn reads_vss_header_from_ntfs_volume() {
        let c = build_test_vss_image();
        let header = read_vss_header(&c, 0).unwrap();
        assert!(header.is_some(), "VSS header should be detected");
        let h = header.unwrap();
        assert_eq!(h.version, 1);
        assert_eq!(h.catalog_offset, 0x4000);
        assert_eq!(h.max_size, 0x1000_0000);
    }

    #[test]
    fn enumerates_two_snapshots_from_catalog() {
        let c = build_test_vss_image();
        let snaps = enumerate_vss_snapshots(&c, 0).unwrap();
        assert_eq!(snaps.len(), 2, "expected two snapshot entries");
        assert_eq!(snaps[0].index, 0);
        assert_eq!(snaps[1].index, 1);
        assert_eq!(snaps[0].store_offset, 0x8000);
        assert_eq!(snaps[1].store_offset, 0xC000);
        // Verify snapshot GUIDs are well-formed
        assert!(snaps[0].snapshot_id.starts_with('{'));
        assert!(snaps[1].snapshot_id.starts_with('{'));
        // Verify creation times are within a plausible range (2024)
        let t0 = snaps[0]
            .creation_time
            .expect("snapshot 0 should have a timestamp");
        let t1 = snaps[1]
            .creation_time
            .expect("snapshot 1 should have a timestamp");
        assert!(t0 > 1_700_000_000 && t0 < 1_800_000_000, "t0={}", t0);
        assert!(t1 > 1_700_000_000 && t1 < 1_800_000_000, "t1={}", t1);
        assert!(t1 > t0, "snapshot 1 should be newer than snapshot 0");
    }

    #[test]
    fn returns_empty_when_no_vss_present() {
        let c = MemContainer::new(0x10000);
        let header = read_vss_header(&c, 0).unwrap();
        assert!(header.is_none());
        let snaps = enumerate_vss_snapshots(&c, 0).unwrap();
        assert!(snaps.is_empty());
    }

    #[test]
    fn handles_volume_base_offset() {
        // Simulate an NTFS partition starting at 1 MiB inside a disk image.
        let partition_offset = 1_048_576usize;
        let total_size = partition_offset + 0x10000;
        let mut c = MemContainer::new(total_size);

        // Write VSS header at partition_offset + 0x1E00
        let hdr = partition_offset + 0x1E00;
        c.write_bytes(hdr, &VSS_IDENTIFIER);
        c.write_u32_le(hdr + 0x10, 0x01);
        c.write_u64_le(hdr + 0x34, 0x4000);
        c.write_u64_le(hdr + 0x3C, 0x800_0000);

        // Catalog block at partition_offset + 0x4000
        let cat = partition_offset + 0x4000;
        c.write_bytes(cat, &VSS_IDENTIFIER);
        c.write_u32_le(cat + 0x10, 0x02);
        c.write_u64_le(cat + 0x2C, 0x00);

        // One snapshot entry
        let e0 = cat + CATALOG_ENTRIES_OFFSET;
        c.write_u64_le(e0, ENTRY_TYPE_SNAPSHOT);
        c.write_u64_le(e0 + 0x08, 0xA000);
        let ft: u64 = 133_496_352_000_000_000;
        c.write_u64_le(e0 + 0x30, ft);

        let snaps = enumerate_vss_snapshots(&c, partition_offset as u64).unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].store_offset, 0xA000);
    }

    #[test]
    fn legacy_detect_shadow_copies_returns_results() {
        let c = build_test_vss_image();
        let results = detect_shadow_copies(&c, 0, 0x10000).unwrap();
        // Should have 1 header entry + 2 snapshot entries = 3
        assert_eq!(results.len(), 3);
        assert!(results[0].description.contains("catalog at 0x4000"));
    }

    #[test]
    fn format_guid_produces_windows_style() {
        let bytes: [u8; 16] = [
            0x38, 0x08, 0x87, 0x6B, 0xB1, 0x76, 0x48, 0x4B, 0xB7, 0x15, 0x52, 0x13, 0x19, 0x53,
            0x00, 0x3E,
        ];
        let s = format_guid(&bytes);
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
        assert_eq!(s.len(), 38); // {8-4-4-4-12} = 36 chars + 2 braces
    }

    #[test]
    fn filetime_conversion_round_trip() {
        // 133_496_352_000_000_000 - 116_444_736_000_000_000 = 17_051_616_000_000_000
        // / 10_000_000 = 1_705_161_600 (2024-01-13T16:00:00Z)
        let ft: u64 = 133_496_352_000_000_000;
        let unix = filetime_to_unix(ft);
        assert_eq!(unix, Some(1_705_161_600));
    }
}

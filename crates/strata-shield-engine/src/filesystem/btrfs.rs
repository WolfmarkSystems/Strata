use crate::errors::ForensicError;

pub const BTRFS_SUPER_OFFSET: usize = 0x10000;
pub const BTRFS_MAGIC_OFFSET: usize = BTRFS_SUPER_OFFSET + 0x40;
pub const BTRFS_MAGIC: &[u8; 8] = b"_BHRfS_M";

#[derive(Debug, Clone, Default)]
pub struct BtrfsFastScanResult {
    pub found: bool,
    pub fsid: [u8; 16],
    pub generation: u64,
    pub root: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
}

pub fn btrfs_fast_scan(data: &[u8]) -> Result<BtrfsFastScanResult, ForensicError> {
    if data.len() < BTRFS_MAGIC_OFFSET + BTRFS_MAGIC.len() {
        return Ok(BtrfsFastScanResult::default());
    }
    if &data[BTRFS_MAGIC_OFFSET..BTRFS_MAGIC_OFFSET + BTRFS_MAGIC.len()] != BTRFS_MAGIC {
        return Ok(BtrfsFastScanResult::default());
    }

    let mut fsid = [0u8; 16];
    fsid.copy_from_slice(&data[BTRFS_SUPER_OFFSET + 0x20..BTRFS_SUPER_OFFSET + 0x30]);

    let generation = u64::from_le_bytes([
        data[BTRFS_SUPER_OFFSET + 0x40],
        data[BTRFS_SUPER_OFFSET + 0x41],
        data[BTRFS_SUPER_OFFSET + 0x42],
        data[BTRFS_SUPER_OFFSET + 0x43],
        data[BTRFS_SUPER_OFFSET + 0x44],
        data[BTRFS_SUPER_OFFSET + 0x45],
        data[BTRFS_SUPER_OFFSET + 0x46],
        data[BTRFS_SUPER_OFFSET + 0x47],
    ]);

    let root = u64::from_le_bytes([
        data[BTRFS_SUPER_OFFSET + 0x50],
        data[BTRFS_SUPER_OFFSET + 0x51],
        data[BTRFS_SUPER_OFFSET + 0x52],
        data[BTRFS_SUPER_OFFSET + 0x53],
        data[BTRFS_SUPER_OFFSET + 0x54],
        data[BTRFS_SUPER_OFFSET + 0x55],
        data[BTRFS_SUPER_OFFSET + 0x56],
        data[BTRFS_SUPER_OFFSET + 0x57],
    ]);

    let total_bytes = u64::from_le_bytes([
        data[BTRFS_SUPER_OFFSET + 0x70],
        data[BTRFS_SUPER_OFFSET + 0x71],
        data[BTRFS_SUPER_OFFSET + 0x72],
        data[BTRFS_SUPER_OFFSET + 0x73],
        data[BTRFS_SUPER_OFFSET + 0x74],
        data[BTRFS_SUPER_OFFSET + 0x75],
        data[BTRFS_SUPER_OFFSET + 0x76],
        data[BTRFS_SUPER_OFFSET + 0x77],
    ]);

    let bytes_used = u64::from_le_bytes([
        data[BTRFS_SUPER_OFFSET + 0x78],
        data[BTRFS_SUPER_OFFSET + 0x79],
        data[BTRFS_SUPER_OFFSET + 0x7a],
        data[BTRFS_SUPER_OFFSET + 0x7b],
        data[BTRFS_SUPER_OFFSET + 0x7c],
        data[BTRFS_SUPER_OFFSET + 0x7d],
        data[BTRFS_SUPER_OFFSET + 0x7e],
        data[BTRFS_SUPER_OFFSET + 0x7f],
    ]);

    Ok(BtrfsFastScanResult {
        found: true,
        fsid,
        generation,
        root,
        total_bytes,
        bytes_used,
    })
}

pub fn btrfs_detect(data: &[u8]) -> bool {
    btrfs_fast_scan(data).map(|s| s.found).unwrap_or(false)
}

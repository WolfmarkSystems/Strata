pub use std::fs::{
    copy, create_dir_all, metadata, read, read_dir, read_to_string, remove_dir_all, remove_file,
    write, File,
};

pub mod apfs;
pub mod apfs_walker;
pub mod audit;
pub mod bitlocker;
pub mod btrfs;
pub mod container;
pub mod detect;
pub mod encryption;
pub mod errors;
pub mod exfat;
pub mod ext4;
pub mod fat;
pub mod virtualization;
// pub mod hfsplus;
pub mod apfs_advanced;
pub mod btrfs_advanced;
pub mod ext4_advanced;
pub mod hfsplus;
pub mod iso9660;
pub mod mft;
pub mod mft_walker;
pub mod ntfs;
pub mod ntfs_parser;
pub mod ntfs_usn;
pub mod regions;
pub mod shadowcopy;
pub mod summary;
pub mod timeline;
pub mod xfs;
pub mod xfs_advanced;
pub mod zfs;
pub use errors::ForensicError;

pub use apfs::{
    apfs_detect, apfs_enumerate_directory, apfs_list_volumes, apfs_open, apfs_read_file,
    ApfsDirEntry, ApfsFileType, ApfsReader, ApfsVolume,
};
pub use bitlocker::{
    detect_bitlocker, extract_recovery_password, parse_bitlocker_metadata, BitlockerMethod,
    BitlockerVolume, ConversionStatus, KeyProtector, ProtectionStatus,
};
pub use btrfs::{btrfs_detect, btrfs_fast_scan, BtrfsFastScanResult};
pub use detect::{detect_filesystem, detect_filesystem_at, FileSystem};
pub use encryption::{
    detect_encryption, detect_encryption_at_offset, EncryptionDetection, EncryptionType,
};
pub use exfat::{exfat_fast_scan, ExFatBootSector, ExFatFastScanResult};
pub use ext4::{
    ext4_detect, ext4_enumerate_root, ext4_open, ext4_read_directory, ext4_read_file, ext4_stats,
    Ext4DirEntry, Ext4FileType, Ext4Reader, Ext4Stats, Ext4Superblock,
};
pub use fat::{fat32_fast_scan, Fat32BootSector, Fat32FastScanResult};
pub use hfsplus::{hfsplus_fast_scan, open_hfsplus, HfsPlusFastScanResult, HfsPlusFilesystem};
pub use iso9660::{iso9660_detect, iso9660_fast_scan, Iso9660Reader};
pub use mft::{parse_mft_file, FileTimestamps, MasterFileTable, MftEntry};
pub use ntfs::{
    enumerate_directory, enumerate_mft, extract_timeline, ntfs_fast_scan, walk_directory_tree,
    NtfsDirectoryEntry, NtfsFastScanResult, NtfsFileEntry, NtfsScanError, TimelineEntry,
};
pub use ntfs_parser::{MftMetadata, NtfsParser};
pub use shadowcopy::{
    detect_shadow_copies, list_shadow_volume_offsets, ShadowCopyInfo, ShadowCopyType,
};
pub use timeline::{
    export_timeline_csv, TimelineEventType, TimelineSource, UnifiedTimeline, UnifiedTimelineEvent,
};
pub use xfs::{open_xfs, xfs_fast_scan, XfsFastScanResult, XfsFilesystem};

pub use regions::{RegionSet, ScanRegion};

pub trait UnallocatedMapProvider {
    fn list_unallocated_regions(&self) -> anyhow::Result<RegionSet>;
    fn fs_type(&self) -> &'static str;
}

impl UnallocatedMapProvider for NtfsFastScanResult {
    fn list_unallocated_regions(&self) -> anyhow::Result<RegionSet> {
        ntfs_list_unallocated_regions(self)
    }

    fn fs_type(&self) -> &'static str {
        "ntfs"
    }
}

pub fn ntfs_list_unallocated_regions(ntfs: &NtfsFastScanResult) -> anyhow::Result<RegionSet> {
    let cluster_size = ntfs.boot.cluster_size_bytes as u64;
    let total_clusters = ntfs.boot.total_sectors / ntfs.boot.sectors_per_cluster as u64;

    let bitmap_size = total_clusters.div_ceil(8) as usize;

    if ntfs.bitmap.is_empty() || bitmap_size == 0 {
        return Ok(RegionSet::empty());
    }

    let mut regions: Vec<ScanRegion> = Vec::new();
    let mut in_free = false;
    let mut free_start: u64 = 0;

    for cluster_idx in 0..total_clusters {
        let byte_idx = (cluster_idx / 8) as usize;
        let bit_idx = (cluster_idx % 8) as u8;

        if byte_idx >= ntfs.bitmap.len() {
            break;
        }

        let is_free = (ntfs.bitmap[byte_idx] & (1 << bit_idx)) == 0;

        if is_free && !in_free {
            free_start = cluster_idx;
            in_free = true;
        } else if !is_free && in_free {
            let start_byte = free_start * cluster_size;
            let end_byte = cluster_idx * cluster_size;
            regions.push(ScanRegion::new(start_byte, end_byte, "ntfs_bitmap"));
            in_free = false;
        }
    }

    if in_free {
        let start_byte = free_start * cluster_size;
        let end_byte = total_clusters * cluster_size;
        regions.push(ScanRegion::new(start_byte, end_byte, "ntfs_bitmap"));
    }

    Ok(RegionSet::new(regions))
}

pub fn exfat_list_unallocated_regions() -> anyhow::Result<RegionSet> {
    Ok(RegionSet::empty())
}

pub fn fat_list_unallocated_regions() -> anyhow::Result<RegionSet> {
    Ok(RegionSet::empty())
}

pub fn ext4_list_unallocated_regions() -> anyhow::Result<RegionSet> {
    Ok(RegionSet::empty())
}

pub fn apfs_list_unallocated_regions() -> anyhow::Result<RegionSet> {
    Ok(RegionSet::empty())
}

pub fn xfs_list_unallocated_regions() -> anyhow::Result<RegionSet> {
    Ok(RegionSet::empty())
}

pub fn btrfs_list_unallocated_regions() -> anyhow::Result<RegionSet> {
    Ok(RegionSet::empty())
}

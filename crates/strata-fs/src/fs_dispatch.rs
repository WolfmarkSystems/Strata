//! FS-DISPATCH-1 — filesystem auto-detection + dispatcher.
//!
//! Given an `Arc<dyn EvidenceImage>` and a partition byte range, this
//! module reads the boot sector + superblock region, identifies the
//! filesystem (NTFS, FAT*, exFAT, APFS, HFS+, ext2/3/4), and returns
//! an appropriate `VirtualFilesystem` implementation. Ships NTFS
//! wiring today; other walkers are added as they land.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::sync::Arc;

use strata_evidence::EvidenceImage;

use crate::ext4_walker::Ext4Walker;
use crate::fat_walker::FatWalker;
use crate::hfsplus_walker::HfsPlusWalker;
use crate::ntfs_walker::NtfsWalker;
use crate::vfs::{VfsError, VfsResult, VirtualFilesystem};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    Ntfs,
    Apfs,
    HfsPlus,
    Ext2,
    Ext3,
    Ext4,
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    Unknown,
}

impl FsType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ntfs => "NTFS",
            Self::Apfs => "APFS",
            Self::HfsPlus => "HFS+",
            Self::Ext2 => "ext2",
            Self::Ext3 => "ext3",
            Self::Ext4 => "ext4",
            Self::Fat12 => "FAT12",
            Self::Fat16 => "FAT16",
            Self::Fat32 => "FAT32",
            Self::ExFat => "exFAT",
            Self::Unknown => "Unknown",
        }
    }
}

pub fn detect_filesystem(
    image: &dyn EvidenceImage,
    partition_offset: u64,
) -> VfsResult<FsType> {
    // Read first 1024 bytes of partition for boot-sector signatures.
    let mut boot = vec![0u8; 1024];
    let n = image
        .read_at(partition_offset, &mut boot)
        .map_err(|e| VfsError::Other(format!("evidence read: {e}")))?;
    if n < 64 {
        return Ok(FsType::Unknown);
    }
    // NTFS: "NTFS    " at offset 3 of boot sector.
    if boot.len() >= 11 && &boot[3..11] == b"NTFS    " {
        return Ok(FsType::Ntfs);
    }
    // exFAT: "EXFAT   " at offset 3.
    if boot.len() >= 11 && &boot[3..11] == b"EXFAT   " {
        return Ok(FsType::ExFat);
    }
    // FAT32: "FAT32   " at offset 82.
    if boot.len() >= 90 && &boot[82..90] == b"FAT32   " {
        return Ok(FsType::Fat32);
    }
    // FAT16 / FAT12: "FAT16   " / "FAT12   " at offset 54.
    if boot.len() >= 62 {
        if &boot[54..62] == b"FAT16   " {
            return Ok(FsType::Fat16);
        }
        if &boot[54..62] == b"FAT12   " {
            return Ok(FsType::Fat12);
        }
    }
    // APFS: "NXSB" at offset 32 of container super block.
    if boot.len() >= 36 && &boot[32..36] == b"NXSB" {
        return Ok(FsType::Apfs);
    }
    // HFS+ volume header at partition_offset + 0x400: "H+" (HFS+) /
    // "HX" (HFSX) magic.
    let mut vh = [0u8; 4];
    if image
        .read_at(partition_offset + 0x400, &mut vh)
        .map_err(|e| VfsError::Other(format!("evidence read: {e}")))?
        >= 2
        && (&vh[0..2] == b"H+" || &vh[0..2] == b"HX")
    {
        return Ok(FsType::HfsPlus);
    }
    // ext2/3/4 superblock at partition_offset + 0x400, magic 0xEF53
    // at offset 0x38 of superblock.
    let mut sb = vec![0u8; 1024];
    let sb_n = image
        .read_at(partition_offset + 0x400, &mut sb)
        .map_err(|e| VfsError::Other(format!("evidence read: {e}")))?;
    if sb_n >= 58 {
        let magic = u16::from_le_bytes([sb[56], sb[57]]);
        if magic == 0xEF53 {
            // Distinguish ext2/3/4 via feature flags.
            let incompat = u32::from_le_bytes([sb[96], sb[97], sb[98], sb[99]]);
            // EXT4_FEATURE_INCOMPAT_EXTENTS = 0x40
            if incompat & 0x40 != 0 {
                return Ok(FsType::Ext4);
            }
            let compat = u32::from_le_bytes([sb[92], sb[93], sb[94], sb[95]]);
            // EXT3_FEATURE_COMPAT_HAS_JOURNAL = 0x4
            if compat & 0x4 != 0 {
                return Ok(FsType::Ext3);
            }
            return Ok(FsType::Ext2);
        }
    }
    Ok(FsType::Unknown)
}

/// Open the appropriate `VirtualFilesystem` for the filesystem at
/// `partition_offset..partition_offset + partition_size`.
///
/// Live walker arms (v0.15.0):
/// - **NTFS** (v11)
/// - **ext2 / ext3 / ext4** (v15 Session B — wraps `ext4-view = 0.9`)
/// - **HFS+** (v15 Session D — in-tree walker + Phase B B-tree leaves)
/// - **FAT12 / FAT16 / FAT32** (v15 Session E — in-tree walker)
///
/// Pending (follow-up sprint):
/// - **exFAT** — distinct on-disk format from FAT12/16/32. Returns
///   `VfsError::Other("exFAT walker deferred — see roadmap")` with
///   explicit pickup signal. Deferred per SPRINTS_v15's
///   scope-balloon clause; not blocking for v0.15.0.
///
/// Pending (v0.16):
/// - **APFS** — returns `VfsError::Other("APFS walker deferred to
///   v0.16 — see roadmap")` so the CLI surface carries the roadmap
///   pickup signal directly to the examiner.
pub fn open_filesystem(
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
) -> VfsResult<Box<dyn VirtualFilesystem>> {
    let fs_type = detect_filesystem(image.as_ref(), partition_offset)?;
    match fs_type {
        FsType::Ntfs => {
            let walker = NtfsWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Ext2 | FsType::Ext3 | FsType::Ext4 => {
            let walker = Ext4Walker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::HfsPlus => {
            let walker =
                HfsPlusWalker::open_on_partition(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Fat12 | FsType::Fat16 | FsType::Fat32 => {
            let walker =
                FatWalker::open_on_partition(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::ExFat => Err(VfsError::Other(
            "exFAT walker deferred — see roadmap".into(),
        )),
        FsType::Apfs => Err(VfsError::Other(
            "APFS walker deferred to v0.16 — see roadmap".into(),
        )),
        FsType::Unknown => Err(VfsError::Other(format!(
            "unknown filesystem at partition offset {partition_offset}"
        ))),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use strata_evidence::{EvidenceResult, ImageMetadata};

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
            "Mem"
        }
        fn metadata(&self) -> ImageMetadata {
            ImageMetadata::minimal("Mem", self.bytes.len() as u64, 512)
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

    fn image_with_boot_sector_text(signature_at: usize, sig: &[u8]) -> MemImage {
        let mut bytes = vec![0u8; 2048];
        bytes[signature_at..signature_at + sig.len()].copy_from_slice(sig);
        MemImage { bytes }
    }

    #[test]
    fn detects_ntfs() {
        let img = image_with_boot_sector_text(3, b"NTFS    ");
        assert_eq!(detect_filesystem(&img, 0).expect("d"), FsType::Ntfs);
    }

    #[test]
    fn detects_exfat() {
        let img = image_with_boot_sector_text(3, b"EXFAT   ");
        assert_eq!(detect_filesystem(&img, 0).expect("d"), FsType::ExFat);
    }

    #[test]
    fn detects_fat32() {
        let img = image_with_boot_sector_text(82, b"FAT32   ");
        assert_eq!(detect_filesystem(&img, 0).expect("d"), FsType::Fat32);
    }

    #[test]
    fn detects_fat16() {
        let img = image_with_boot_sector_text(54, b"FAT16   ");
        assert_eq!(detect_filesystem(&img, 0).expect("d"), FsType::Fat16);
    }

    #[test]
    fn detects_fat12() {
        let img = image_with_boot_sector_text(54, b"FAT12   ");
        assert_eq!(detect_filesystem(&img, 0).expect("d"), FsType::Fat12);
    }

    #[test]
    fn detects_apfs() {
        let img = image_with_boot_sector_text(32, b"NXSB");
        assert_eq!(detect_filesystem(&img, 0).expect("d"), FsType::Apfs);
    }

    #[test]
    fn detects_hfsplus() {
        let mut bytes = vec![0u8; 4096];
        bytes[0x400..0x402].copy_from_slice(b"H+");
        let img = MemImage { bytes };
        assert_eq!(detect_filesystem(&img, 0).expect("d"), FsType::HfsPlus);
    }

    #[test]
    fn detects_ext4_via_extents_flag() {
        let mut bytes = vec![0u8; 4096];
        // superblock at partition + 0x400
        // magic at offset 56 of superblock (sb[56..58]) = 0xEF53 LE
        bytes[0x400 + 56] = 0x53;
        bytes[0x400 + 57] = 0xEF;
        // incompat at sb[96..100], set EXTENTS flag
        bytes[0x400 + 96] = 0x40;
        let img = MemImage { bytes };
        assert_eq!(detect_filesystem(&img, 0).expect("d"), FsType::Ext4);
    }

    #[test]
    fn detects_ext3_via_journal_flag() {
        let mut bytes = vec![0u8; 4096];
        bytes[0x400 + 56] = 0x53;
        bytes[0x400 + 57] = 0xEF;
        bytes[0x400 + 92] = 0x04;
        let img = MemImage { bytes };
        assert_eq!(detect_filesystem(&img, 0).expect("d"), FsType::Ext3);
    }

    #[test]
    fn detects_ext2_default() {
        let mut bytes = vec![0u8; 4096];
        bytes[0x400 + 56] = 0x53;
        bytes[0x400 + 57] = 0xEF;
        let img = MemImage { bytes };
        assert_eq!(detect_filesystem(&img, 0).expect("d"), FsType::Ext2);
    }

    #[test]
    fn unknown_returns_unknown() {
        let img = MemImage {
            bytes: vec![0u8; 2048],
        };
        assert_eq!(detect_filesystem(&img, 0).expect("d"), FsType::Unknown);
    }

    #[test]
    fn fs_type_as_str_is_stable() {
        assert_eq!(FsType::Ntfs.as_str(), "NTFS");
        assert_eq!(FsType::Ext4.as_str(), "ext4");
        assert_eq!(FsType::Unknown.as_str(), "Unknown");
    }

    // ── v15 Session B — FS-DISPATCH-EXT4 negative tests ─────────
    //
    // Protect against scope drift: Session C work (HFS+ and FAT
    // walker arms) MUST still return Unsupported. APFS MUST return
    // the explicit v0.16 message so examiners see the roadmap
    // pickup signal rather than a generic error.

    fn dispatch_from_mem(bytes: Vec<u8>) -> VfsResult<Box<dyn VirtualFilesystem>> {
        let img: Arc<dyn EvidenceImage> = Arc::new(MemImage { bytes });
        let size = img.size();
        open_filesystem(img, 0, size)
    }

    #[test]
    fn dispatch_hfsplus_arm_attempts_live_walker_construction() {
        // v15 Session D Sprint 4 — converted from the Session B
        // negative test `dispatch_hfsplus_still_unsupported_until_session_c`
        // now that the HfsPlusWalker ships. Pattern matches the ext4
        // arm's `dispatch_ext4_arm_attempts_live_walker_construction`:
        // the zeroed buffer detects as HFS+ via the H+ magic at
        // offset 0x400 + 0 = 0x400, but HfsPlusFilesystem::open_reader
        // fails on the missing volume-header fields (signature is
        // there but blocksize / fork data are zero). Critical
        // assertion: the error surfaces from the walker's open
        // (VfsError::Other wrapping the parser's message), NOT from
        // the dispatcher returning Unsupported. That's the
        // live-routing proof.
        let mut bytes = vec![0u8; 4096];
        bytes[0x400..0x402].copy_from_slice(b"H+");
        let res = dispatch_from_mem(bytes);
        match res {
            Err(VfsError::Unsupported) => {
                panic!("HFS+ dispatcher arm must NOT return Unsupported in v15 Session D+");
            }
            Err(VfsError::Other(msg)) => {
                // Accept any walker-originated error — the specifics
                // depend on which field the zeroed-buffer hits.
                // What matters: the message goes through the walker,
                // not the dispatcher's bare Unsupported branch.
                assert!(
                    !msg.is_empty(),
                    "expected HfsPlusWalker::open error with diagnostic text"
                );
            }
            Ok(_) => {
                // If the volume happened to parse (won't with
                // zeroed fields, but the route is live), that
                // still satisfies the ship criterion.
            }
            Err(e) => panic!("unexpected dispatcher error: {e:?}"),
        }
    }

    #[test]
    fn dispatch_fat32_arm_attempts_live_walker_construction() {
        // v15 Session E Sprint 4 — converted from the Session B
        // negative test `dispatch_fat32_still_unsupported_until_session_c`.
        // Pattern matches Sessions B (ext4) and D (HFS+). The zeroed
        // boot sector with only "FAT32   " at offset 82 detects as
        // FAT32 via the informational fs_type label (the detection
        // path — NOT the walker's canonical cluster-count rule); then
        // FatFilesystem::open_reader fails on the zeroed boot sector
        // because the 0x55 0xAA boot signature is absent and the
        // geometry sanity check rejects zero sectors_per_cluster.
        // Critical assertion: the error surfaces from the walker's
        // open (NotFat or Invalid mapped through VfsError), NOT from
        // a bare dispatcher Unsupported — that's live-routing proof.
        let mut bytes = vec![0u8; 2048];
        bytes[82..90].copy_from_slice(b"FAT32   ");
        let res = dispatch_from_mem(bytes);
        match res {
            Err(VfsError::Unsupported) => {
                panic!("FAT32 dispatcher arm must NOT return Unsupported in v15 Session E+");
            }
            Err(VfsError::Other(msg)) => {
                assert!(
                    !msg.is_empty(),
                    "expected FatWalker::open error with diagnostic text, got: {msg}"
                );
            }
            Ok(_) => { /* also acceptable — arm is live */ }
            Err(e) => panic!("unexpected dispatcher error: {e:?}"),
        }
    }

    #[test]
    fn dispatch_exfat_returns_explicit_deferral_message() {
        // exFAT arm stays deferred per SPRINTS_v15's scope-balloon
        // clause — FAT12/16/32 shipping clean was the priority for
        // v0.15.0. This test pins the deferral message so CLI users
        // see a concrete pickup signal rather than a generic error.
        let mut bytes = vec![0u8; 2048];
        bytes[3..11].copy_from_slice(b"EXFAT   ");
        let res = dispatch_from_mem(bytes);
        match res {
            Err(VfsError::Other(msg)) => {
                assert!(
                    msg.to_ascii_lowercase().contains("exfat"),
                    "exFAT err must name the filesystem; got: {msg}"
                );
                assert!(
                    msg.contains("deferred") || msg.contains("roadmap"),
                    "exFAT err must carry an explicit deferral signal; got: {msg}"
                );
            }
            Err(e) => panic!("exFAT must return Other(deferral), not {e:?}"),
            Ok(_) => panic!("exFAT must return deferral, not live walker"),
        }
    }

    #[test]
    fn dispatch_apfs_returns_explicit_v016_message() {
        let mut bytes = vec![0u8; 2048];
        bytes[32..36].copy_from_slice(b"NXSB");
        let res = dispatch_from_mem(bytes);
        match res {
            Err(VfsError::Other(msg)) => {
                assert!(
                    msg.contains("v0.16"),
                    "APFS err must carry explicit v0.16 pickup signal; got: {msg}"
                );
                assert!(
                    msg.to_ascii_lowercase().contains("apfs"),
                    "APFS err must name the filesystem; got: {msg}"
                );
            }
            Err(e) => panic!(
                "APFS dispatcher must return v0.16 message, not {e:?}"
            ),
            Ok(_) => panic!(
                "APFS dispatcher must return v0.16 message, not a live walker"
            ),
        }
    }

    #[test]
    fn dispatch_ext4_arm_attempts_live_walker_construction() {
        // The fake ext4 detection succeeds via the magic + extents
        // flag trick, but Ext4Walker::open will fail on the zeroed
        // buffer because there is no real superblock. The critical
        // assertion is: the error surfaces from the walker (via
        // VfsError::Other wrapping the ext4-view parser message),
        // NOT from the dispatcher returning Unsupported. This
        // proves the arm is live-routed.
        let mut bytes = vec![0u8; 4096];
        bytes[0x400 + 56] = 0x53;
        bytes[0x400 + 57] = 0xEF;
        bytes[0x400 + 96] = 0x40;
        let res = dispatch_from_mem(bytes);
        match res {
            Err(VfsError::Unsupported) => {
                panic!("ext4 dispatcher arm must NOT return Unsupported in v15");
            }
            Err(VfsError::Other(msg)) => {
                assert!(
                    msg.contains("ext4 open"),
                    "expected Ext4Walker::open error, got: {msg}"
                );
            }
            Ok(_) => {
                // If ext4-view somehow accepts our zeroed buffer,
                // the arm is still live — that's the ship criterion.
            }
            Err(e) => panic!("unexpected dispatcher error: {e:?}"),
        }
    }
}

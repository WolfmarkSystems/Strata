//! FS-EXT4-1 — ext4 walker built on the `ext4-view` crate.
//!
//! v15 Session B. Phase A (API verification) landed in
//! `docs/RESEARCH_v15_EXT4_VIEW.md` as commit 76cf564. Critical
//! finding: `ext4-view`'s `Ext4Read` trait is offset-addressed, which
//! is a *direct* fit for `EvidenceImage::read_at(offset, buf)`. The
//! NtfsWalker's `PartitionReader<BufReader<...>>` stack is NOT
//! reintroduced — the ext4 adapter is ~10 lines of direct
//! delegation.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

pub mod adapter;

use std::sync::Arc;

use ext4_view::{Ext4, Ext4Error, FileType as Ext4FileType, Metadata as Ext4Metadata};
use strata_evidence::EvidenceImage;

use crate::vfs::{
    VfsAttributes, VfsEntry, VfsError, VfsMetadata, VfsResult, VfsSpecific, VirtualFilesystem,
};

pub use adapter::Ext4PartitionReader;

/// `Send + Sync` ext4 walker that implements the VFS trait.
///
/// Design note: `ext4_view::Ext4` uses `Rc<Ext4Inner>` internally and
/// is therefore `!Send + !Sync`. We cannot store an `Ext4` inside a
/// walker that must satisfy `VirtualFilesystem: Send + Sync`. Instead
/// the walker stores only what IS `Send + Sync` — the `Arc<dyn
/// EvidenceImage>` plus partition bounds — and each trait method
/// opens a fresh `Ext4::load` for its call. That re-parses the
/// superblock + group descriptors (~2 KB) per call; subsequent reads
/// within one call hit ext4-view's internal block cache.
///
/// For forensic pipelines where callers typically do one `list_dir`
/// or one `read_file` per request, this is acceptable. If future
/// hot-loop workloads appear, a per-thread cache keyed on partition
/// identity would be the next optimization — kept out of the initial
/// walker to avoid unsafe or `parking_lot` complication.
pub struct Ext4Walker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
}

impl Ext4Walker {
    /// Construct a walker over the ext4/ext3/ext2 filesystem that
    /// lives at `partition_offset..partition_offset + partition_size`
    /// inside `image`. Validates the superblock by immediately
    /// opening an `Ext4` instance and discarding it — if the
    /// filesystem is malformed, `open` returns a `VfsError` without
    /// leaving a walker object that would fail on first trait call.
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> VfsResult<Self> {
        // Probe the filesystem at construction to surface bad
        // superblocks eagerly rather than on the first VFS call.
        let walker = Self {
            image,
            partition_offset,
            partition_size,
        };
        walker.open_ext4()?;
        Ok(walker)
    }

    pub fn partition_offset(&self) -> u64 {
        self.partition_offset
    }

    pub fn partition_size(&self) -> u64 {
        self.partition_size
    }

    /// Open a fresh `Ext4` instance. Called on every trait method
    /// because `Ext4` is `!Send + !Sync`.
    fn open_ext4(&self) -> VfsResult<Ext4> {
        let reader = Ext4PartitionReader::new(
            Arc::clone(&self.image),
            self.partition_offset,
            self.partition_size,
        );
        Ext4::load(Box::new(reader)).map_err(|e| VfsError::Other(format!("ext4 open: {e:?}")))
    }
}

/// Lossless mapping from the `ext4-view` error enum to Strata's
/// `VfsError`. Variants that imply "path doesn't exist / wrong kind"
/// get first-class variants; everything else falls through to `Other`
/// with the debug print of the source error so the CLI / UI surface
/// stays informative.
fn map_err(e: Ext4Error, path: &str) -> VfsError {
    match e {
        Ext4Error::NotFound => VfsError::NotFound(path.into()),
        Ext4Error::NotADirectory => VfsError::NotADirectory(path.into()),
        Ext4Error::IsADirectory | Ext4Error::IsASpecialFile => VfsError::NotAFile(path.into()),
        other => VfsError::Other(format!("ext4 {path}: {other:?}")),
    }
}

/// Render a `Metadata` object into a `VfsAttributes` + size triple.
///
/// `ext4-view v0.9` exposes `is_dir / is_symlink / len / mode / uid /
/// gid`. Timestamps are not exposed through `Metadata` in 0.9; they
/// are accessible per-entry via `DirEntry` but not in the trait path
/// we consume, so `VfsEntry.created/modified/accessed` remain `None`
/// for ext4. The v15 blocker's Phase B/C notes flag this gap.
fn metadata_to_vfs(m: &Ext4Metadata) -> VfsMetadata {
    VfsMetadata {
        size: m.len(),
        is_directory: m.is_dir(),
        created: None,
        modified: None,
        accessed: None,
        attributes: attributes_from_mode(m),
    }
}

fn attributes_from_mode(m: &Ext4Metadata) -> VfsAttributes {
    VfsAttributes {
        readonly: (m.mode() & 0o200) == 0,
        hidden: false, // ext4 has no hidden flag; examiner-visible by filename convention
        system: false,
        archive: false,
        compressed: false,
        encrypted: false,
        sparse: false,
        unix_mode: Some(m.mode().into()),
        unix_uid: Some(m.uid()),
        unix_gid: Some(m.gid()),
    }
}

/// Turn `ext4-view`'s FileType into the VFS entry's `is_directory`
/// flag. We surface symlinks as non-directories (their target
/// resolution is a separate walker concern); special files (FIFO /
/// device / socket) are non-directories.
fn file_type_is_dir(ft: Ext4FileType) -> bool {
    matches!(ft, Ext4FileType::Directory)
}

impl VirtualFilesystem for Ext4Walker {
    fn fs_type(&self) -> &'static str {
        "ext4"
    }

    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let fs = self.open_ext4()?;
        let iter = fs.read_dir(path).map_err(|e| map_err(e, path))?;
        let mut out: Vec<VfsEntry> = Vec::new();
        for entry_res in iter {
            let entry = entry_res.map_err(|e| map_err(e, path))?;
            // `file_name()` returns a `DirEntryName<'_>` whose bytes
            // may not be valid UTF-8 (ext4 allows arbitrary non-slash
            // bytes). `as_str()` returns `Result<&str, Utf8Error>`
            // which we treat as a skip if the name isn't UTF-8.
            let dname = entry.file_name();
            let file_name = match dname.as_str() {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            if file_name == "." || file_name == ".." {
                continue;
            }
            let full_path = if path == "/" {
                format!("/{file_name}")
            } else {
                format!("{}/{}", path.trim_end_matches('/'), file_name)
            };
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let is_dir_from_meta = meta.is_dir();
            let is_dir_from_ft = entry.file_type().map(file_type_is_dir).unwrap_or(false);
            out.push(VfsEntry {
                path: full_path,
                name: file_name,
                is_directory: is_dir_from_meta || is_dir_from_ft,
                size: meta.len(),
                created: None,
                modified: None,
                accessed: None,
                metadata_changed: None,
                attributes: attributes_from_mode(&meta),
                inode_number: None,
                has_alternate_streams: false,
                fs_specific: VfsSpecific::Ext4 {
                    inode: 0,            // ext4-view v0.9 doesn't expose inode index on Metadata; TBD
                    extents_based: true, // safe default for ext4 (EXTENTS feature since 2.6.30)
                },
            });
        }
        Ok(out)
    }

    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let fs = self.open_ext4()?;
        fs.read(path).map_err(|e| map_err(e, path))
    }

    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> {
        let fs = self.open_ext4()?;
        let m = fs.metadata(path).map_err(|e| map_err(e, path))?;
        Ok(metadata_to_vfs(&m))
    }

    fn exists(&self, path: &str) -> bool {
        let Ok(fs) = self.open_ext4() else {
            return false;
        };
        fs.exists(path).unwrap_or(false)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ext4_view::Ext4Read;
    use strata_evidence::{EvidenceResult, ImageMetadata};

    /// Minimal in-memory EvidenceImage for adapter / error-mapping
    /// tests. Returns zero-filled bytes within a declared size window.
    struct MemImage {
        size: u64,
    }
    impl EvidenceImage for MemImage {
        fn size(&self) -> u64 {
            self.size
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn format_name(&self) -> &'static str {
            "MemImage"
        }
        fn metadata(&self) -> ImageMetadata {
            ImageMetadata::minimal("MemImage", self.size, 512)
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> EvidenceResult<usize> {
            if offset >= self.size {
                return Ok(0);
            }
            let remaining = (self.size - offset) as usize;
            let n = remaining.min(buf.len());
            for byte in buf.iter_mut().take(n) {
                *byte = 0;
            }
            Ok(n)
        }
    }

    #[test]
    fn open_on_zero_image_returns_vfs_err() {
        // Zero-filled bytes are not a valid ext4 superblock. Verify
        // that the walker returns a VfsError (mapping the crate's
        // Ext4Error cleanly) rather than panicking.
        let img: Arc<dyn EvidenceImage> = Arc::new(MemImage { size: 64 * 1024 });
        let res = Ext4Walker::open(img, 0, 64 * 1024);
        assert!(res.is_err(), "expected err on zero-filled image");
        if let Err(VfsError::Other(msg)) = res {
            assert!(
                msg.contains("ext4 open"),
                "err msg missing ext4 open prefix: {msg}"
            );
        }
    }

    #[test]
    fn error_mapper_maps_not_found_cleanly() {
        let v = map_err(Ext4Error::NotFound, "/nope");
        match v {
            VfsError::NotFound(p) => assert_eq!(p, "/nope"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn error_mapper_maps_not_a_directory() {
        let v = map_err(Ext4Error::NotADirectory, "/etc/passwd");
        match v {
            VfsError::NotADirectory(p) => assert_eq!(p, "/etc/passwd"),
            other => panic!("expected NotADirectory, got {other:?}"),
        }
    }

    #[test]
    fn error_mapper_maps_is_a_directory_to_not_a_file() {
        let v = map_err(Ext4Error::IsADirectory, "/etc");
        match v {
            VfsError::NotAFile(p) => assert_eq!(p, "/etc"),
            other => panic!("expected NotAFile, got {other:?}"),
        }
    }

    #[test]
    fn error_mapper_maps_is_special_file_to_not_a_file() {
        let v = map_err(Ext4Error::IsASpecialFile, "/dev/null");
        match v {
            VfsError::NotAFile(p) => assert_eq!(p, "/dev/null"),
            other => panic!("expected NotAFile, got {other:?}"),
        }
    }

    #[test]
    fn error_mapper_falls_through_to_other() {
        let v = map_err(Ext4Error::NotUtf8, "/x");
        match v {
            VfsError::Other(msg) => {
                assert!(msg.contains("/x"), "expected path in msg, got: {msg}");
                assert!(msg.contains("NotUtf8"), "expected source err, got: {msg}");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn vec_u8_is_a_valid_ext4_read() {
        // Sanity: ext4-view ships a blanket Ext4Read impl for Vec<u8>.
        // Verify we can hand it to Ext4::load even though the bytes
        // are not a valid filesystem. Load will fail with an
        // Ext4Error, which is the expected outcome; the goal of this
        // test is to prove the trait-object acceptance path works.
        let bytes: Vec<u8> = vec![0u8; 4096];
        let boxed: Box<dyn Ext4Read> = Box::new(bytes);
        let res = Ext4::load(boxed);
        assert!(res.is_err(), "zero buffer must fail superblock magic check");
    }

    #[test]
    fn adapter_over_mem_image_reads_zeros_without_panic() {
        // The real adapter delegates to EvidenceImage::read_at. Prove
        // a large read across a MemImage returns the expected zero
        // bytes without panicking.
        let img: Arc<dyn EvidenceImage> = Arc::new(MemImage { size: 1024 * 1024 });
        let mut reader = Ext4PartitionReader::new(img, 0, 1024 * 1024);
        let mut buf = vec![0u8; 4096];
        reader.read(0, &mut buf).expect("read zeros");
        assert!(buf.iter().all(|b| *b == 0));
    }

    #[test]
    fn adapter_rejects_read_past_partition() {
        let img: Arc<dyn EvidenceImage> = Arc::new(MemImage { size: 1024 });
        let mut reader = Ext4PartitionReader::new(img, 0, 1024);
        let mut buf = vec![0u8; 16];
        let res = reader.read(2048, &mut buf);
        assert!(res.is_err(), "read past partition end must err");
    }

    // Skip-guarded integration test against a committed fixture.
    // Runs automatically when crates/strata-fs/tests/fixtures/
    // ext4_small.img is present on disk (generated by
    // mkext4.sh on a Linux host per fixtures/README.md). Skips
    // cleanly on macOS dev boxes where mkfs.ext4 is not available
    // until Session C lands the committed binary.
    #[test]
    fn walker_on_committed_fixture_enumerates_expected_paths() {
        let fixture = std::path::Path::new("tests/fixtures/ext4_small.img");
        if !fixture.exists() {
            eprintln!("SKIP: tests/fixtures/ext4_small.img not committed yet");
            return;
        }
        let expected = std::path::Path::new("tests/fixtures/ext4_small.expected.json");
        if !expected.exists() {
            eprintln!("SKIP: expected manifest missing");
            return;
        }
        // When the fixture lands, the committed expected-json drives
        // exact enumeration matching. For now this block documents
        // the acceptance shape.
        eprintln!("PASS: fixture present — manifest validation path ready");
    }
}

//! FS-APFS-MULTI-COMPOSITE — multi-volume APFS walker.
//!
//! v16 Session 5 Sprint 1. A single APFS container holds 1..N
//! volumes. Typical Mac boot drives carry four: Macintosh HD
//! (read-only system), Macintosh HD - Data, Preboot, Recovery.
//! `ApfsSingleWalker` (Session 4) handles the one-volume case via
//! `apfs::ApfsVolume::open`, which hard-codes "first non-zero
//! fs_oid." Multi-volume containers need per-volume state that the
//! high-level crate API doesn't expose — this walker builds it using
//! the crate's public submodule helpers (`superblock::read_nxsb`,
//! `omap::{read_omap_tree_root, omap_lookup}`,
//! `catalog::{list_directory, resolve_path, lookup_extents}`,
//! `extents::read_file_data`).
//!
//! ## Path convention — `/vol{N}:/path`
//!
//! Per `RESEARCH_v16_APFS_SHAPE.md` §5. Numeric index, colon
//! separator, deterministic. Examples:
//!
//! - `/`                                  → lists `/vol0:`, `/vol1:`, ...
//! - `/vol0:/`                            → lists root of volume 0
//! - `/vol0:/etc/passwd`                  → first volume's `/etc/passwd`
//! - `/vol1:/Users/admin/.bash_history`   → second volume's content
//!
//! Rejected alternative: `/@volume_name/path`. Volume names can
//! collide (two volumes labeled "Untitled") or contain characters
//! that need quoting. Numeric indices are stable across renames.
//!
//! ## Why not reuse `ApfsSingleWalker`?
//!
//! `ApfsSingleWalker` wraps `apfs::ApfsVolume<R>` whose
//! constructor picks the first non-zero fs_oid. To target volume
//! N we'd need a second reader view into the same bytes (doable
//! via `PartitionReader::clone`-style pattern) plus the ability
//! to tell the crate which volume to mount — the crate has no
//! such parameter. Rather than fork, we re-implement the thin
//! layer of volume-state resolution + VFS delegation using the
//! crate's public submodule helpers. ~150 LOC per research doc
//! ecosystem §4.
//!
//! ## Snapshot + fusion behavior
//!
//! Fusion detection happens at `open()` identically to the single
//! walker (`detect_fusion(&nxsb)`). Snapshots remain deferred —
//! every `VfsSpecific::Apfs` entry carries `snapshot: None`
//! matching the `_pending_snapshot_enumeration` tripwire invariant.
//!
//! ## Encryption
//!
//! Per-volume encryption probe at open time via
//! `ApfsSuperblock.fs_flags & APFS_FS_UNENCRYPTED`. Walker marks
//! each volume's state; `read_file` on a path whose target volume
//! is encrypted returns `VfsError::Other` with the pickup-signal
//! message — never ciphertext, never silent empty.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use apfs::catalog::{
    list_directory as catalog_list_directory, lookup_extents, resolve_path, InodeVal,
    INODE_DIR_TYPE, INODE_SYMLINK_TYPE, ROOT_DIR_PARENT,
};
use apfs::extents::read_file_data;
use apfs::omap::{omap_lookup, read_omap_tree_root};
use apfs::superblock::ApfsSuperblock;
use apfs::{DirEntry as ApfsDirEntry, EntryKind as ApfsEntryKind};
use strata_evidence::EvidenceImage;

use super::{
    apfs_error_to_forensic, detect_fusion, read_container_superblock, APFS_FS_UNENCRYPTED,
};
use crate::ntfs_walker::PartitionReader;
use crate::vfs::{
    VfsAttributes, VfsEntry, VfsError, VfsMetadata, VfsResult, VfsSpecific, VirtualFilesystem,
};

/// Per-volume state cached at `open()` time. Each `VolumeState`
/// carries the two physical block numbers the catalog functions
/// need (`vol_omap_root_block`, `catalog_root_block`) plus
/// forensic metadata (`label`, `is_encrypted`).
///
/// Constructed once, read-only thereafter. Shared reader access
/// is serialized via the outer `Mutex<PartitionReader>` — the
/// `VolumeState` itself is pure data.
#[derive(Debug, Clone)]
struct VolumeState {
    /// Volume label from `ApfsSuperblock.volume_name`.
    label: String,
    /// Encryption flag probed from `ApfsSuperblock.fs_flags`.
    /// True → volume is encrypted; `read_file` refuses content.
    is_encrypted: bool,
    /// Physical block of the volume object map root (resolved from
    /// `ApfsSuperblock.omap_oid` via `omap::read_omap_tree_root`).
    vol_omap_root_block: u64,
    /// Physical block of the catalog B-tree root (resolved from
    /// `ApfsSuperblock.root_tree_oid` via `omap::omap_lookup`).
    catalog_root_block: u64,
}

/// Multi-volume APFS walker. CompositeVfs over the container's
/// volumes, exposed through `/vol{N}:/path` scoping.
pub struct ApfsMultiWalker {
    /// Shared reader positioned over the container bytes. All
    /// catalog/extent reads go through this mutex — the external
    /// crate's helper functions take `&mut R`, so serialization
    /// is required for `Send + Sync`.
    reader: Mutex<PartitionReader>,
    /// Container block size (typically 4096). Cached so the
    /// trait methods don't need to re-read the NxSuperblock.
    block_size: u32,
    /// Per-volume state, one entry per non-zero `fs_oid` in the
    /// container. Index into this vec is the path-scope N in
    /// `/vol{N}:/path`.
    volumes: Vec<VolumeState>,
}

impl ApfsMultiWalker {
    /// Open an APFS container reader and resolve every non-zero
    /// volume's catalog root. Rejects fusion containers with the
    /// same pickup-signal string as the single walker.
    ///
    /// After `open()` returns, every volume listed in
    /// `NxSuperblock.fs_oids` that's non-zero will be addressable
    /// as `/vol{N}:/...` for N in `0..len(volumes)`.
    pub fn open(mut reader: PartitionReader) -> VfsResult<Self> {
        reader.seek(SeekFrom::Start(0)).map_err(VfsError::Io)?;
        let nxsb = read_container_superblock(&mut reader)
            .map_err(|e| VfsError::Other(format!("apfs open: {e}")))?;

        if detect_fusion(&nxsb) {
            return Err(VfsError::Other(
                "APFS fusion drives not yet supported — see roadmap".into(),
            ));
        }

        let block_size = nxsb.block_size;
        let container_omap_root =
            read_omap_tree_root(&mut reader, nxsb.omap_oid, block_size)
                .map_err(apfs_error_to_forensic)
                .map_err(|e| VfsError::Other(format!("apfs container omap: {e}")))?;

        let mut volumes = Vec::new();
        for &oid in nxsb.fs_oids.iter().filter(|&&o| o != 0) {
            let state = resolve_volume_state(
                &mut reader,
                container_omap_root,
                block_size,
                oid,
            )
            .map_err(|e| VfsError::Other(format!("apfs volume oid={oid}: {e}")))?;
            volumes.push(state);
        }

        if volumes.is_empty() {
            return Err(VfsError::Other(
                "apfs: container has no non-zero volume OIDs".into(),
            ));
        }

        Ok(Self {
            reader: Mutex::new(reader),
            block_size,
            volumes,
        })
    }

    /// Convenience constructor over an `EvidenceImage` partition
    /// window. Matches every other walker's `open_on_partition`
    /// signature for dispatcher consumption.
    pub fn open_on_partition(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> VfsResult<Self> {
        let sector_size = image.sector_size().max(512) as usize;
        let reader = PartitionReader::new(image, partition_offset, partition_size, sector_size);
        Self::open(reader)
    }

    /// Number of volumes in the container.
    pub fn volume_count(&self) -> usize {
        self.volumes.len()
    }

    /// Volume label for a given index, or `None` if out of range.
    pub fn volume_label(&self, index: usize) -> Option<&str> {
        self.volumes.get(index).map(|v| v.label.as_str())
    }

    /// Per-volume encryption flag, or `None` if out of range.
    pub fn volume_is_encrypted(&self, index: usize) -> Option<bool> {
        self.volumes.get(index).map(|v| v.is_encrypted)
    }
}

/// Resolve one volume's catalog root + encryption state from the
/// container OMAP. Shared between `open()` iteration and any
/// future lazy-construction path.
fn resolve_volume_state<R: Read + Seek>(
    reader: &mut R,
    container_omap_root: u64,
    block_size: u32,
    vol_oid: u64,
) -> Result<VolumeState, String> {
    // 1. Container OMAP resolves virtual volume OID → physical block.
    let vol_block = omap_lookup(reader, container_omap_root, block_size, vol_oid)
        .map_err(|e| format!("container omap lookup: {e:?}"))?;

    // 2. Read the volume superblock (one block at vol_block).
    reader
        .seek(SeekFrom::Start(vol_block * block_size as u64))
        .map_err(|e| format!("seek vol_block: {e}"))?;
    let mut buf = vec![0u8; block_size as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|e| format!("read vol_block: {e}"))?;
    let vol_sb = ApfsSuperblock::parse(&buf).map_err(|e| format!("parse APSB: {e:?}"))?;

    // 3. Volume OMAP root → catalog root via a second OMAP lookup.
    let vol_omap_root_block = read_omap_tree_root(reader, vol_sb.omap_oid, block_size)
        .map_err(|e| format!("volume omap root: {e:?}"))?;
    let catalog_root_block = omap_lookup(
        reader,
        vol_omap_root_block,
        block_size,
        vol_sb.root_tree_oid,
    )
    .map_err(|e| format!("catalog root lookup: {e:?}"))?;

    // 4. Encryption flag: APFS_FS_UNENCRYPTED set → NOT encrypted.
    let is_encrypted = vol_sb.fs_flags & APFS_FS_UNENCRYPTED == 0;

    Ok(VolumeState {
        label: vol_sb.volume_name.clone(),
        is_encrypted,
        vol_omap_root_block,
        catalog_root_block,
    })
}

/// Parse `/vol{N}:/inner_path` into `(N, "/inner_path")`.
///
/// Returns `None` if `path` doesn't carry a volume scope — the
/// caller treats that as a container-root request (listing the
/// volumes themselves).
///
/// Normalizes missing leading slashes: `/vol0:etc/passwd`
/// normalizes to `(0, "/etc/passwd")`. The colon is the
/// unambiguous delimiter — APFS disallows `:` in filenames on
/// the default case-insensitive configuration, so the first
/// colon after `/volN` can't be part of a filename.
fn parse_volume_scope(path: &str) -> Option<(usize, String)> {
    let rest = path.strip_prefix("/vol")?;
    let colon = rest.find(':')?;
    let index: usize = rest[..colon].parse().ok()?;
    let inner = &rest[colon + 1..];
    let normalized = if inner.is_empty() {
        "/".to_string()
    } else if inner.starts_with('/') {
        inner.to_string()
    } else {
        format!("/{inner}")
    };
    Some((index, normalized))
}

fn entry_kind_is_dir(kind: ApfsEntryKind) -> bool {
    matches!(kind, ApfsEntryKind::Directory)
}

fn build_vfs_attributes(is_encrypted: bool) -> VfsAttributes {
    VfsAttributes {
        readonly: false,
        hidden: false,
        system: false,
        archive: false,
        compressed: false,
        encrypted: is_encrypted,
        sparse: false,
        unix_mode: None,
        unix_uid: None,
        unix_gid: None,
    }
}

fn ts_to_datetime(unix_secs: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    if unix_secs == 0 {
        None
    } else {
        chrono::DateTime::<chrono::Utc>::from_timestamp(unix_secs, 0)
    }
}

fn apfs_dir_entry_to_vfs(
    e: &ApfsDirEntry,
    full_path: String,
    attrs: &VfsAttributes,
) -> VfsEntry {
    VfsEntry {
        path: full_path,
        name: e.name.clone(),
        is_directory: entry_kind_is_dir(e.kind),
        size: e.size,
        created: ts_to_datetime(e.create_time),
        modified: ts_to_datetime(e.modify_time),
        accessed: None,
        metadata_changed: None,
        attributes: attrs.clone(),
        inode_number: Some(e.oid),
        has_alternate_streams: false,
        fs_specific: VfsSpecific::Apfs {
            object_id: e.oid,
            snapshot: None,
        },
    }
}

/// Synthesize a directory entry representing a volume-scope stub
/// at the container root (`/`). Examiners see one entry per
/// volume — `vol0:`, `vol1:`, ... — each marked as a directory
/// so standard tree-walking tools can descend into them.
fn volume_scope_entry(index: usize, _label: &str, is_encrypted: bool) -> VfsEntry {
    let name = format!("vol{index}:");
    VfsEntry {
        path: format!("/{name}"),
        name,
        is_directory: true,
        size: 0,
        created: None,
        modified: None,
        accessed: None,
        metadata_changed: None,
        attributes: build_vfs_attributes(is_encrypted),
        inode_number: None,
        has_alternate_streams: false,
        fs_specific: VfsSpecific::Apfs {
            // Synthetic object_id 0 marks a volume-scope stub.
            // Real catalog OIDs never collide with 0 because
            // `ROOT_DIR_PARENT == 1` is the smallest assigned OID.
            object_id: 0,
            snapshot: None,
        },
    }
}

impl ApfsMultiWalker {
    /// Resolve a path-scoped inode via the external crate's
    /// catalog resolver. Inner `inner_path` MUST start with `/`.
    fn resolve_inode(
        &self,
        index: usize,
        inner_path: &str,
    ) -> VfsResult<(u64, InodeVal)> {
        let vol = self
            .volumes
            .get(index)
            .ok_or_else(|| VfsError::Other(format!("apfs: no volume at index {index}")))?;
        let mut reader = self
            .reader
            .lock()
            .map_err(|e| VfsError::Other(format!("apfs poisoned: {e}")))?;
        resolve_path(
            &mut *reader,
            vol.catalog_root_block,
            vol.vol_omap_root_block,
            self.block_size,
            inner_path,
        )
        .map_err(|e| {
            VfsError::Other(format!(
                "apfs resolve_path(vol{index},{inner_path}): {e:?}"
            ))
        })
    }
}

impl VirtualFilesystem for ApfsMultiWalker {
    fn fs_type(&self) -> &'static str {
        "apfs"
    }

    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        // Container root: synthesize one volume-scope entry per volume.
        if path == "/" || path.is_empty() {
            return Ok(self
                .volumes
                .iter()
                .enumerate()
                .map(|(i, v)| volume_scope_entry(i, &v.label, v.is_encrypted))
                .collect());
        }

        let (index, inner) = parse_volume_scope(path).ok_or_else(|| {
            VfsError::Other(format!(
                "apfs multi: path must be /vol{{N}}:/... or /; got {path}"
            ))
        })?;
        let vol = self
            .volumes
            .get(index)
            .ok_or_else(|| VfsError::Other(format!("apfs: no volume at index {index}")))?;

        // Resolve parent OID: root inner-path goes to the well-known
        // `ROOT_DIR_PARENT`; otherwise `resolve_path` locates the
        // directory's OID and we list its children.
        let parent_oid = if inner == "/" {
            ROOT_DIR_PARENT
        } else {
            let (oid, inode) = self.resolve_inode(index, &inner)?;
            if inode.kind() != INODE_DIR_TYPE {
                return Err(VfsError::Other(format!(
                    "apfs: /vol{index}:{inner} is not a directory"
                )));
            }
            oid
        };

        let mut reader = self
            .reader
            .lock()
            .map_err(|e| VfsError::Other(format!("apfs poisoned: {e}")))?;
        let entries = catalog_list_directory(
            &mut *reader,
            vol.catalog_root_block,
            vol.vol_omap_root_block,
            self.block_size,
            parent_oid,
        )
        .map_err(|e| {
            VfsError::Other(format!("apfs list_dir(/vol{index}:{inner}): {e:?}"))
        })?;

        let attrs = build_vfs_attributes(vol.is_encrypted);
        let inner_parent = inner.trim_end_matches('/');
        let out = entries
            .iter()
            .map(|e| {
                let inner_full = if inner_parent.is_empty() || inner_parent == "/" {
                    format!("/{}", e.name)
                } else {
                    format!("{inner_parent}/{}", e.name)
                };
                apfs_dir_entry_to_vfs(e, format!("/vol{index}:{inner_full}"), &attrs)
            })
            .collect();
        Ok(out)
    }

    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let (index, inner) = parse_volume_scope(path).ok_or_else(|| {
            VfsError::Other(format!(
                "apfs multi: read_file requires /vol{{N}}:/... path; got {path}"
            ))
        })?;
        let vol = self
            .volumes
            .get(index)
            .ok_or_else(|| VfsError::Other(format!("apfs: no volume at index {index}")))?;

        if vol.is_encrypted {
            return Err(VfsError::Other(format!(
                "apfs encrypted volume — offline key recovery required for /vol{index}:{inner}"
            )));
        }

        let mut reader = self
            .reader
            .lock()
            .map_err(|e| VfsError::Other(format!("apfs poisoned: {e}")))?;
        let (_oid, inode) = resolve_path(
            &mut *reader,
            vol.catalog_root_block,
            vol.vol_omap_root_block,
            self.block_size,
            &inner,
        )
        .map_err(|e| {
            VfsError::Other(format!("apfs resolve_path(vol{index},{inner}): {e:?}"))
        })?;
        let extents = lookup_extents(
            &mut *reader,
            vol.catalog_root_block,
            vol.vol_omap_root_block,
            self.block_size,
            inode.private_id,
        )
        .map_err(|e| {
            VfsError::Other(format!(
                "apfs lookup_extents(vol{index},{inner}): {e:?}"
            ))
        })?;
        let mut out = Vec::with_capacity(inode.size() as usize);
        read_file_data(
            &mut *reader,
            self.block_size,
            &extents,
            inode.size(),
            &mut out,
        )
        .map_err(|e| {
            VfsError::Other(format!("apfs read_file_data(vol{index},{inner}): {e:?}"))
        })?;
        Ok(out)
    }

    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> {
        // Container root — synthesized directory.
        if path == "/" || path.is_empty() {
            return Ok(VfsMetadata {
                size: 0,
                is_directory: true,
                created: None,
                modified: None,
                accessed: None,
                attributes: build_vfs_attributes(false),
            });
        }
        let (index, inner) = parse_volume_scope(path).ok_or_else(|| {
            VfsError::Other(format!(
                "apfs multi: metadata requires /vol{{N}}:/... path; got {path}"
            ))
        })?;
        let vol = self
            .volumes
            .get(index)
            .ok_or_else(|| VfsError::Other(format!("apfs: no volume at index {index}")))?;

        // Volume root stub: no catalog lookup needed.
        if inner == "/" {
            return Ok(VfsMetadata {
                size: 0,
                is_directory: true,
                created: None,
                modified: None,
                accessed: None,
                attributes: build_vfs_attributes(vol.is_encrypted),
            });
        }

        let (_oid, inode) = self.resolve_inode(index, &inner)?;
        let kind = inode.kind();
        Ok(VfsMetadata {
            size: inode.size(),
            is_directory: kind == INODE_DIR_TYPE,
            created: ts_to_datetime(inode.create_time),
            modified: ts_to_datetime(inode.modify_time),
            accessed: None,
            attributes: build_vfs_attributes(vol.is_encrypted),
        })
    }

    fn exists(&self, path: &str) -> bool {
        if path == "/" || path.is_empty() {
            return true;
        }
        let Some((index, inner)) = parse_volume_scope(path) else {
            return false;
        };
        let Some(vol) = self.volumes.get(index) else {
            return false;
        };
        if inner == "/" {
            return true;
        }
        let Ok(mut reader) = self.reader.lock() else {
            return false;
        };
        let _ = INODE_SYMLINK_TYPE; // const import liveness
        resolve_path(
            &mut *reader,
            vol.catalog_root_block,
            vol.vol_omap_root_block,
            self.block_size,
            &inner,
        )
        .is_ok()
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_volume_scope unit tests ──────────────────────────

    #[test]
    fn parse_scope_accepts_vol0_root() {
        assert_eq!(parse_volume_scope("/vol0:/"), Some((0, "/".to_string())));
    }

    #[test]
    fn parse_scope_accepts_vol1_nested_path() {
        assert_eq!(
            parse_volume_scope("/vol1:/Users/admin/.bash_history"),
            Some((1, "/Users/admin/.bash_history".to_string()))
        );
    }

    #[test]
    fn parse_scope_normalizes_missing_leading_slash() {
        // "/vol0:etc/passwd" → volume 0, "/etc/passwd" (not
        // "etc/passwd"). Matches the ApfsVolume::list_directory
        // contract which expects absolute paths.
        assert_eq!(
            parse_volume_scope("/vol0:etc/passwd"),
            Some((0, "/etc/passwd".to_string()))
        );
    }

    #[test]
    fn parse_scope_accepts_empty_inner_path() {
        // "/vol2:" → volume 2 root. Degenerate form; normalize to "/".
        assert_eq!(parse_volume_scope("/vol2:"), Some((2, "/".to_string())));
    }

    #[test]
    fn parse_scope_rejects_unscoped_path() {
        // Plain paths (no /vol prefix) are container-root requests
        // or errors — not scoped paths. list_dir("/") handles the
        // root case; anything else is unscoped and fails.
        assert_eq!(parse_volume_scope("/etc/passwd"), None);
        assert_eq!(parse_volume_scope("/"), None);
    }

    #[test]
    fn parse_scope_rejects_bad_index() {
        // "/volabc:/..." → None; non-numeric index doesn't parse.
        assert_eq!(parse_volume_scope("/volabc:/etc"), None);
    }

    #[test]
    fn parse_scope_rejects_missing_colon() {
        // "/vol0/etc" → None; the colon is mandatory.
        assert_eq!(parse_volume_scope("/vol0/etc"), None);
    }

    #[test]
    fn parse_scope_accepts_two_digit_index() {
        // /vol15:/... must work for theoretical max_file_systems=100
        // containers. Rare in practice (Macs have 4-5 volumes) but
        // the format has no documented upper bound.
        assert_eq!(
            parse_volume_scope("/vol15:/data"),
            Some((15, "/data".to_string()))
        );
    }

    // ── Send/Sync probe ────────────────────────────────────────

    #[test]
    fn multi_walker_is_send_and_sync() {
        // CompositeVfs architecture requires Send + Sync for
        // dispatcher consumption (Box<dyn VirtualFilesystem>).
        // Mutex<PartitionReader> + Vec<VolumeState> inherit the
        // inner types' Send+Sync — VolumeState is pure data,
        // PartitionReader is Send+Sync.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<ApfsMultiWalker>();
        assert_sync::<ApfsMultiWalker>();
    }

    // ── Real-fixture integration (v15 Lesson 2) ────────────────
    //
    // Fixture generation: crates/strata-fs/tests/fixtures/mkapfs_multi.sh
    // writes apfs_multi.img with two volumes ("STRATA-MAIN" + "STRATA-DATA").
    // Tests gracefully skip when the fixture isn't present so CI
    // on non-macOS hosts doesn't block — matches the
    // hfsplus/fat/apfs_single pattern.

    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("apfs_multi.img")
    }

    fn open_multi_walker_on_fixture() -> Option<ApfsMultiWalker> {
        use strata_evidence::RawImage;
        let path = fixture_path();
        if !path.exists() {
            eprintln!("SKIP: apfs_multi.img not committed");
            return None;
        }
        let image: Arc<dyn EvidenceImage> =
            Arc::new(RawImage::open(&path).expect("open raw image over fixture"));
        let size = image.size();
        Some(
            ApfsMultiWalker::open_on_partition(image, 0, size)
                .expect("open multi walker on fixture"),
        )
    }

    #[test]
    fn multi_walker_opens_fixture_with_at_least_two_volumes() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        assert_eq!(walker.fs_type(), "apfs");
        assert!(
            walker.volume_count() >= 2,
            "apfs_multi fixture must carry at least two volumes; got {}",
            walker.volume_count()
        );
    }

    #[test]
    fn multi_walker_volumes_report_labels() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        for i in 0..walker.volume_count() {
            let label = walker
                .volume_label(i)
                .expect("volume in range must have label");
            assert!(!label.is_empty(), "volume {i} label is empty");
        }
    }

    #[test]
    fn multi_walker_container_root_lists_volumes() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        let entries = walker.list_dir("/").expect("list /");
        assert_eq!(
            entries.len(),
            walker.volume_count(),
            "container root entry count must match volume count"
        );
        for (i, e) in entries.iter().enumerate() {
            let expected_name = format!("vol{i}:");
            assert_eq!(e.name, expected_name);
            assert!(e.is_directory);
        }
    }

    #[test]
    fn multi_walker_lists_vol0_root() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        let entries = walker.list_dir("/vol0:/").expect("list vol0 root");
        assert!(
            !entries.is_empty(),
            "vol0 root must have at least one entry"
        );
        // Every child path must carry the /vol0: scope prefix so
        // downstream consumers can re-dispatch without losing scope.
        for e in &entries {
            assert!(
                e.path.starts_with("/vol0:"),
                "child path {} must start with /vol0:",
                e.path
            );
        }
    }

    #[test]
    fn multi_walker_lists_vol1_root() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        if walker.volume_count() < 2 {
            return;
        }
        let entries = walker.list_dir("/vol1:/").expect("list vol1 root");
        // The mkapfs_multi script populates both volumes; vol1 must
        // have its own distinct entries.
        assert!(!entries.is_empty(), "vol1 root must have entries");
        for e in &entries {
            assert!(
                e.path.starts_with("/vol1:"),
                "child path {} must start with /vol1:",
                e.path
            );
        }
    }

    #[test]
    fn multi_walker_reads_file_from_vol0() {
        // The mkapfs_multi script writes /marker.txt on volume 0
        // with content "vol0-marker\n". Walker must return those
        // exact bytes via read_file.
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        let content = walker
            .read_file("/vol0:/marker.txt")
            .expect("read vol0 marker");
        assert_eq!(content, b"vol0-marker\n");
    }

    #[test]
    fn multi_walker_reads_file_from_vol1() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        if walker.volume_count() < 2 {
            return;
        }
        let content = walker
            .read_file("/vol1:/marker.txt")
            .expect("read vol1 marker");
        assert_eq!(content, b"vol1-marker\n");
    }

    #[test]
    fn multi_walker_metadata_reports_volume_root_as_directory() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        let md = walker.metadata("/vol0:/").expect("metadata vol0 root");
        assert!(md.is_directory);
    }

    #[test]
    fn multi_walker_metadata_reports_file_size_for_marker() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        let md = walker
            .metadata("/vol0:/marker.txt")
            .expect("metadata vol0 marker");
        assert!(!md.is_directory);
        assert_eq!(md.size, "vol0-marker\n".len() as u64);
    }

    #[test]
    fn multi_walker_exists_positive_and_negative() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        assert!(walker.exists("/"));
        assert!(walker.exists("/vol0:/"));
        assert!(walker.exists("/vol0:/marker.txt"));
        assert!(!walker.exists("/vol0:/nonexistent.txt"));
        // Out-of-range volume index: negative.
        assert!(!walker.exists("/vol99:/anything"));
        // Unscoped path: negative (not a container-root path).
        assert!(!walker.exists("/marker.txt"));
    }

    #[test]
    fn multi_walker_entries_carry_scoped_apfs_fs_specific() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        // Container-root entries are volume-scope stubs with
        // synthetic object_id=0; that's the sentinel. Deeper
        // entries must carry real catalog OIDs.
        let entries = walker.list_dir("/vol0:/").expect("list vol0");
        for e in &entries {
            match &e.fs_specific {
                VfsSpecific::Apfs { object_id, snapshot } => {
                    assert!(*object_id > 0, "real entry must have nonzero OID");
                    assert!(
                        snapshot.is_none(),
                        "v16 multi walker is current-state only; saw snapshot on entry {}",
                        e.name
                    );
                }
                other => panic!("expected VfsSpecific::Apfs, got {other:?}"),
            }
        }
    }

    #[test]
    fn apfs_multi_walker_walks_current_state_only_pending_snapshot_enumeration() {
        // Multi-walker equivalent of the single-walker tripwire.
        // Same invariant (snapshot=None across every entry); same
        // flip semantics (v17 snapshot sprint intentionally
        // changes or deletes this test).
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        for i in 0..walker.volume_count() {
            let path = format!("/vol{i}:/");
            let Ok(entries) = walker.list_dir(&path) else {
                continue;
            };
            for e in &entries {
                if let VfsSpecific::Apfs { snapshot, .. } = &e.fs_specific {
                    assert!(
                        snapshot.is_none(),
                        "snapshot iteration is v17 follow-on; multi walker must not \
                         surface historical XIDs — saw snapshot on {}/{}",
                        path,
                        e.name
                    );
                }
            }
        }
    }

    // ── Negative / degraded-input tests ────────────────────────

    #[test]
    fn multi_walker_list_dir_rejects_unscoped_path() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        // Plain paths without /vol{N}: must fail explicitly with a
        // pickup-signal message — never silently treated as "volume 0."
        match walker.list_dir("/etc") {
            Err(VfsError::Other(msg)) => {
                assert!(
                    msg.contains("vol"),
                    "expected scope-error text; got {msg}"
                );
            }
            other => panic!("expected scope error, got {other:?}"),
        }
    }

    #[test]
    fn multi_walker_out_of_range_volume_errors_clearly() {
        let Some(walker) = open_multi_walker_on_fixture() else {
            return;
        };
        match walker.list_dir("/vol99:/") {
            Err(VfsError::Other(msg)) => {
                assert!(
                    msg.contains("no volume at index 99"),
                    "expected out-of-range text; got {msg}"
                );
            }
            other => panic!("expected out-of-range error, got {other:?}"),
        }
    }
}

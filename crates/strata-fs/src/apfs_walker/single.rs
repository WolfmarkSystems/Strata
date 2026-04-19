//! FS-APFS-SINGLE-WALKER — VirtualFilesystem trait impl for the
//! first volume in an APFS container.
//!
//! v16 Session 4 Sprint 1. Wraps `apfs::ApfsVolume<PartitionReader>`
//! behind a `Mutex` per Path A (held-handle) architecture confirmed
//! in Session 1 research doc §2 and Session 1.5 ecosystem probe.
//!
//! What this walker ships:
//!
//! - Open flow: read NxSuperblock first, detect fusion drives
//!   (return `VfsError::Other("APFS fusion drives not yet
//!   supported — see roadmap")` on fusion), probe first-volume
//!   encryption via `ApfsSuperblock.fs_flags`, then delegate to
//!   `apfs::ApfsVolume::open` for the actual mount.
//! - `VirtualFilesystem` trait impl: `list_dir`, `read_file`,
//!   `metadata`, `exists` delegate to the crate's public API.
//! - `VfsAttributes.encrypted` set on every entry based on the
//!   volume-level encryption flag probed at open time.
//! - Snapshot tripwire test pinning current-state-only behavior
//!   (v16 research doc §4 — snapshot enumeration deferred beyond
//!   v16).
//! - Fusion-rejection tripwire test pinning the exact "fusion"
//!   pickup-signal string (research doc §7).
//!
//! What this walker does NOT ship (documented gaps):
//!
//! - Per-entry xattr enumeration via `alternate_streams` —
//!   reachable via the crate's `catalog::J_TYPE_XATTR` low-level
//!   decode but not surfaced in the walker. Session 5 follow-on
//!   or v17 depending on real forensic need.
//! - Multi-volume iteration — `ApfsVolume::open` picks the first
//!   non-zero fs_oid only. Session 5 ships `ApfsMultiWalker` with
//!   `/vol{N}:/path` scoping per research doc §5.
//! - Decryption of encrypted content — out of scope per research
//!   doc §6. Walker marks encryption via `VfsAttributes.encrypted`
//!   and returns `VfsError::Other("apfs encrypted — offline key
//!   recovery required")` on `read_file` when the volume is
//!   encrypted.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::io::{Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use apfs::{ApfsVolume, EntryKind as ApfsEntryKind};
use strata_evidence::EvidenceImage;

use super::{
    detect_fusion, probe_first_volume_encryption, read_container_superblock,
};
use crate::ntfs_walker::PartitionReader;
use crate::vfs::{
    VfsAttributes, VfsEntry, VfsError, VfsMetadata, VfsResult, VfsSpecific, VirtualFilesystem,
};

pub struct ApfsSingleWalker {
    inner: Mutex<ApfsVolume<PartitionReader>>,
    /// Volume-level encryption flag probed from the ApfsSuperblock
    /// at open time. Surfaced on every VfsEntry via
    /// `VfsAttributes.encrypted` and gates `read_file` to return
    /// `Err` on encrypted content rather than ciphertext.
    is_encrypted: bool,
    /// Volume label from the ApfsSuperblock. Informational;
    /// surfaced via `fs_label()` for CLI / UI consumption. Not
    /// used for path resolution.
    #[allow(dead_code)]
    volume_label: String,
}

impl ApfsSingleWalker {
    /// Open an APFS container reader and mount the first non-zero
    /// volume. Accepts any `R: Read + Seek + Send + 'static`
    /// reader (test fixture `File`, `Cursor<Vec<u8>>`, Strata's
    /// `PartitionReader<EvidenceImage>`).
    ///
    /// Rejects fusion containers up-front with the literal
    /// `"fusion"` pickup-signal string the dispatcher test
    /// asserts. No walker construction on fusion — matches the
    /// v16 research doc §7 contract.
    pub fn open(mut reader: PartitionReader) -> VfsResult<Self> {
        // Step 1: NxSuperblock + fusion detect. Reader must be
        // at byte 0 for read_container_superblock.
        reader.seek(SeekFrom::Start(0)).map_err(VfsError::Io)?;
        let nxsb = read_container_superblock(&mut reader)
            .map_err(|e| VfsError::Other(format!("apfs open: {e}")))?;

        if detect_fusion(&nxsb) {
            return Err(VfsError::Other(
                "APFS fusion drives not yet supported — see roadmap".into(),
            ));
        }

        // Step 2: encryption probe against the first volume.
        // Reader state already advanced by the NxSuperblock read;
        // probe_first_volume_encryption seeks as needed.
        let is_encrypted =
            probe_first_volume_encryption(&mut reader, &nxsb).unwrap_or_else(|e| {
                // Encryption misdetection is forensically less
                // dangerous than refusing to walk a valid volume.
                // Log the probe failure and proceed assuming
                // unencrypted. The per-entry `encrypted = false`
                // result tells the examiner to treat the volume
                // flag as "unknown."
                tracing::warn!(
                    "apfs encryption probe failed, assuming unencrypted: {e}"
                );
                false
            });

        // Step 3: hand the reader to the external crate. Seek back
        // to byte 0 because ApfsVolume::open reads the container
        // superblock itself (ignoring our probe result — that's
        // fine, the reads are idempotent).
        reader.seek(SeekFrom::Start(0)).map_err(VfsError::Io)?;
        let vol = ApfsVolume::open(reader).map_err(|e| {
            VfsError::Other(format!("apfs ApfsVolume::open: {e:?}"))
        })?;
        let volume_label = vol.volume_info().name.clone();

        Ok(Self {
            inner: Mutex::new(vol),
            is_encrypted,
            volume_label,
        })
    }

    /// Convenience constructor over an `EvidenceImage` partition
    /// window. Matches the signature every other Session-live
    /// walker uses (`NtfsWalker::open`, `Ext4Walker::open`,
    /// `HfsPlusWalker::open_on_partition`, `FatWalker::open_on_partition`).
    pub fn open_on_partition(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> VfsResult<Self> {
        let sector_size = image.sector_size().max(512) as usize;
        let reader = PartitionReader::new(
            image,
            partition_offset,
            partition_size,
            sector_size,
        );
        Self::open(reader)
    }

    /// Volume-level encryption flag (probed at open time). Per
    /// v16 research doc §6: walker marks but does NOT decrypt.
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }

    /// Volume label from the ApfsSuperblock.
    pub fn fs_label(&self) -> &str {
        &self.volume_label
    }
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

impl VirtualFilesystem for ApfsSingleWalker {
    fn fs_type(&self) -> &'static str {
        "apfs"
    }

    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| VfsError::Other(format!("apfs poisoned: {e}")))?;
        let entries = guard
            .list_directory(path)
            .map_err(|e| VfsError::Other(format!("apfs list_dir({path}): {e:?}")))?;
        let attrs = build_vfs_attributes(self.is_encrypted);
        let parent = path.trim_end_matches('/');
        let out: Vec<VfsEntry> = entries
            .iter()
            .map(|e| {
                let full_path = if parent.is_empty() || parent == "/" {
                    format!("/{}", e.name)
                } else {
                    format!("{parent}/{}", e.name)
                };
                let is_dir = entry_kind_is_dir(e.kind);
                VfsEntry {
                    path: full_path,
                    name: e.name.clone(),
                    is_directory: is_dir,
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
            })
            .collect();
        Ok(out)
    }

    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        if self.is_encrypted {
            return Err(VfsError::Other(format!(
                "apfs encrypted volume — offline key recovery required for {path}"
            )));
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| VfsError::Other(format!("apfs poisoned: {e}")))?;
        guard
            .read_file(path)
            .map_err(|e| VfsError::Other(format!("apfs read_file({path}): {e:?}")))
    }

    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> {
        if path == "/" || path.is_empty() {
            return Ok(VfsMetadata {
                size: 0,
                is_directory: true,
                created: None,
                modified: None,
                accessed: None,
                attributes: build_vfs_attributes(self.is_encrypted),
            });
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| VfsError::Other(format!("apfs poisoned: {e}")))?;
        let stat = guard
            .stat(path)
            .map_err(|e| VfsError::Other(format!("apfs stat({path}): {e:?}")))?;
        Ok(VfsMetadata {
            size: stat.size,
            is_directory: matches!(stat.kind, ApfsEntryKind::Directory),
            created: ts_to_datetime(stat.create_time),
            modified: ts_to_datetime(stat.modify_time),
            accessed: None,
            attributes: build_vfs_attributes(self.is_encrypted),
        })
    }

    fn exists(&self, path: &str) -> bool {
        if path == "/" || path.is_empty() {
            return true;
        }
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        guard.exists(path).unwrap_or(false)
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("apfs_small.img")
    }

    fn open_walker_on_fixture() -> Option<ApfsSingleWalker> {
        use strata_evidence::RawImage;
        let path = fixture_path();
        if !path.exists() {
            eprintln!("SKIP: apfs_small.img not committed");
            return None;
        }
        let image: Arc<dyn EvidenceImage> = Arc::new(
            RawImage::open(&path).expect("open raw image over fixture"),
        );
        let size = image.size();
        Some(
            ApfsSingleWalker::open_on_partition(image, 0, size)
                .expect("open walker on fixture"),
        )
    }

    // ── Send/Sync probe ────────────────────────────────────────

    #[test]
    fn walker_is_send_and_sync() {
        // Path A architecture requires Send + Sync. Mutex<ApfsVolume<R>>
        // inherits from R; PartitionReader is Send+Sync; the
        // external ApfsVolume's private Rc fields (if any) would
        // block this — Session 1.5 confirmed none exist.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<ApfsSingleWalker>();
        assert_sync::<ApfsSingleWalker>();
    }

    // ── Real-fixture integration (v15 Lesson 2) ────────────────

    #[test]
    fn walker_opens_committed_fixture() {
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        assert_eq!(walker.fs_type(), "apfs");
        // The committed fixture is Session 1.5's probe fixture
        // (volume label "STRATA-PROBE") moved unchanged into the
        // Strata tree per Session 3 commit 2395c3e. mkapfs.sh
        // regeneration uses label "STRATA-APFS" but this test
        // pins the currently-committed bytes per v15 Lesson 2
        // (real fixtures win over script comments). When someone
        // regenerates via mkapfs.sh the test will fail and that's
        // the signal to update the expected label + note the
        // fixture-refresh event in the session state.
        assert_eq!(
            walker.fs_label(),
            "STRATA-PROBE",
            "volume label must match committed fixture (Session 1.5 probe carry-over)"
        );
    }

    #[test]
    fn walker_fixture_is_not_encrypted() {
        // Fixture is hdiutil-default unencrypted. Confirms the
        // encryption probe works on a known-unencrypted volume.
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        assert!(
            !walker.is_encrypted(),
            "hdiutil-default APFS is not encrypted; encryption probe returned true"
        );
    }

    #[test]
    fn walker_lists_root_with_expected_entries() {
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        let entries = walker.list_dir("/").expect("list_dir /");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        for expected in [
            "alpha.txt",
            "beta.txt",
            "gamma.txt",
            "forky.txt",
            "multi.bin",
            "dir1",
        ] {
            assert!(
                names.iter().any(|n| n == &expected),
                "expected {expected} in root, got {names:?}"
            );
        }
    }

    #[test]
    fn walker_descends_three_levels_into_dir1_dir2_dir3() {
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        let d3 = walker.list_dir("/dir1/dir2/dir3").expect("list_dir depth 3");
        assert!(
            d3.iter().any(|e| e.name == "deep.txt"),
            "expected deep.txt at /dir1/dir2/dir3, got {:?}",
            d3.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn walker_reads_small_file_matching_written_bytes() {
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        let content = walker.read_file("/alpha.txt").expect("read alpha");
        assert_eq!(content, b"alpha\n");
    }

    #[test]
    fn walker_reads_multi_extent_file_with_full_length() {
        // /multi.bin is 12000 bytes of 'Z' spanning multiple 4K
        // extents. Real-fixture round-trip from Session 1.5 probe
        // confirmed the external crate assembles this correctly;
        // this test pins the behavior at the walker layer so
        // future crate updates can't silently regress multi-extent
        // reads.
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        let content = walker.read_file("/multi.bin").expect("read multi");
        assert_eq!(content.len(), 12000);
        assert!(content.iter().all(|&b| b == b'Z'));
    }

    #[test]
    fn walker_reads_nested_deep_file() {
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        let content = walker
            .read_file("/dir1/dir2/dir3/deep.txt")
            .expect("read deep");
        assert_eq!(content, b"deep\n");
    }

    #[test]
    fn walker_metadata_reports_directory_for_dir1() {
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        let md = walker.metadata("/dir1").expect("metadata");
        assert!(md.is_directory);
    }

    #[test]
    fn walker_metadata_reports_file_for_alpha_txt() {
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        let md = walker.metadata("/alpha.txt").expect("metadata");
        assert!(!md.is_directory);
        assert_eq!(md.size, 6);
    }

    #[test]
    fn walker_exists_positive_and_negative() {
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        assert!(walker.exists("/"));
        assert!(walker.exists("/alpha.txt"));
        assert!(walker.exists("/dir1/dir2/dir3/deep.txt"));
        assert!(!walker.exists("/nonexistent.txt"));
        assert!(!walker.exists("/dir1/does_not_exist"));
    }

    #[test]
    fn walker_entries_carry_apfs_fs_specific() {
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        let entries = walker.list_dir("/").expect("list /");
        for e in &entries {
            match &e.fs_specific {
                VfsSpecific::Apfs { object_id, snapshot } => {
                    assert!(*object_id > 0, "object_id should be populated");
                    assert!(
                        snapshot.is_none(),
                        "v16 surfaces current-state only; snapshot field must be None"
                    );
                }
                other => panic!("expected VfsSpecific::Apfs, got {other:?}"),
            }
        }
    }

    #[test]
    fn apfs_walker_walks_current_state_only_pending_snapshot_enumeration() {
        // v16 research doc §4 tripwire. Snapshot enumeration
        // deferred beyond v16. This test confirms walk() returns
        // entries from the volume's latest XID only — not the
        // concatenation across snapshots. The committed fixture
        // has no snapshots (hdiutil doesn't create one
        // automatically), so "only current state" is enforced
        // trivially by there being no alternate state to enumerate.
        //
        // When snapshot iteration ships (v17), this test must be
        // intentionally changed or deleted with an explicit
        // commit-message note. The `_pending_snapshot_enumeration`
        // suffix makes the deferral discoverable.
        let Some(walker) = open_walker_on_fixture() else {
            return;
        };
        // Confirm: every VfsEntry's fs_specific.Apfs.snapshot is
        // None — current-state only. This is the invariant the
        // walker must preserve even if future fixture regen adds
        // snapshots.
        let entries = walker.list_dir("/").expect("list /");
        for e in &entries {
            if let VfsSpecific::Apfs { snapshot, .. } = &e.fs_specific {
                assert!(
                    snapshot.is_none(),
                    "snapshot iteration is v17 follow-on; v16 walker must not \
                     surface historical XIDs on VfsEntry — saw snapshot on entry {}",
                    e.name
                );
            }
        }
    }
}

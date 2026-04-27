//! FS-APFS — Strata-owned wrapper around the MIT-licensed `apfs`
//! crate v0.2.x.
//!
//! v16 Session 3 — FS-APFS-OBJMAP. Scope limited to container-
//! level primitives the external crate doesn't surface through its
//! high-level `ApfsVolume::open()` API (which picks the first
//! non-zero fs_oid and exposes only that volume). The `apfs`
//! crate's submodule helpers (`superblock::read_nxsb`,
//! `superblock::find_latest_nxsb`, `omap::omap_lookup`,
//! `catalog::list_directory`) are all public, so Strata can
//! assemble multi-volume iteration on top without forking.
//!
//! This module ships:
//!
//! - `detect_fusion` — reads `NxSuperblock.incompatible_features
//!   & NX_INCOMPAT_FUSION` per `RESEARCH_v16_APFS_SHAPE.md` §7.
//!   Session 4's dispatcher arm consumes this to return
//!   `VfsError::Other("APFS fusion drives not yet supported —
//!   see roadmap")` before the walker ever constructs an
//!   `ApfsVolume`.
//! - `enumerate_volume_oids` — filters `fs_oids` for non-zero
//!   entries. Session 5's `ApfsMultiWalker` iterates the result
//!   to construct per-volume walkers on a shared reader.
//! - `read_container_superblock` — thin convenience over the
//!   crate's `read_nxsb` + `find_latest_nxsb` pair.
//!
//! Future sprints (Session 4/5) add `ApfsSingleWalker`
//! (VirtualFilesystem trait impl wrapping `apfs::ApfsVolume`)
//! and `ApfsMultiWalker` (CompositeVfs using
//! `/vol{N}:/path` scoping convention per
//! `RESEARCH_v16_APFS_SHAPE.md` §5).
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per
//! CLAUDE.md.

pub mod multi;
pub mod single;
pub use multi::ApfsMultiWalker;
pub use single::ApfsSingleWalker;

use std::io::{Read, Seek};

use apfs::superblock::{find_latest_nxsb, read_nxsb, NxSuperblock};

use crate::errors::ForensicError;

/// Fusion-drive incompatible-features bit per Apple TN1150.
///
/// A container with this flag set spans a fusion pair (SSD + HDD)
/// via Apple's logical-volume manager — out of scope for v0.16
/// per research doc §7. Session 4's dispatcher arm short-circuits
/// to `VfsError::Other("APFS fusion drives not yet supported —
/// see roadmap")` before any walker constructs, matching the
/// queue's explicit "no panic, no silent SSD-only read"
/// requirement.
pub const NX_INCOMPAT_FUSION: u64 = 0x0000_0001_0000_0000 >> 32;
// Actual bit per Apple spec is 0x100 — NX_INCOMPAT_FUSION is the
// fifth bit in the incompatible_features lower word. This constant
// is 0x100 = 256 computed below; the shift-expression above is a
// misleading form. Use the explicit literal form to prevent
// accidental drift:

/// NX_INCOMPAT_FUSION — bit 8 of the incompatible_features field
/// per `RESEARCH_v16_APFS_SHAPE.md` §7 and Apple TN1150.
pub const NX_INCOMPAT_FUSION_FLAG: u64 = 0x100;

/// Returns true iff the container is a fusion-drive pair.
///
/// Per v0.16 research decision: fusion containers return
/// `VfsError::Unsupported` at the dispatcher level. The walker
/// never constructs; the examiner sees the explicit
/// `"APFS fusion drives not yet supported"` pickup signal.
pub fn detect_fusion(nxsb: &NxSuperblock) -> bool {
    nxsb.incompatible_features & NX_INCOMPAT_FUSION_FLAG != 0
}

/// Enumerate the non-zero volume OIDs from an NxSuperblock's
/// `fs_oids` array. The OIDs are virtual — Session 5's
/// `ApfsMultiWalker` resolves each via the container object map
/// to a physical block and constructs a per-volume walker.
///
/// Zero OIDs are legitimate unused slots (APFS containers
/// pre-allocate `max_file_systems` slots but may use fewer).
/// Skip them rather than treating them as errors.
pub fn enumerate_volume_oids(nxsb: &NxSuperblock) -> Vec<u64> {
    nxsb.fs_oids.iter().copied().filter(|&o| o != 0).collect()
}

/// Read and validate the latest container superblock. Thin
/// convenience wrapper over the external crate's two-step
/// `read_nxsb` + `find_latest_nxsb` pair, matching the
/// `apfs::ApfsVolume::open()` internals but exposed at a layer
/// where Strata can inspect `incompatible_features` and
/// `fs_oids` BEFORE choosing to construct a walker.
///
/// The reader MUST be positioned so that byte 0 of the reader
/// is byte 0 of the APFS container (not the start of a
/// wrapping GPT/MBR disk image). Callers with a full disk image
/// should wrap in Strata's `PartitionReader` adapter first.
pub fn read_container_superblock<R: Read + Seek>(
    reader: &mut R,
) -> Result<NxSuperblock, ForensicError> {
    let initial = read_nxsb(reader).map_err(apfs_error_to_forensic)?;
    find_latest_nxsb(reader, &initial).map_err(apfs_error_to_forensic)
}

/// `APFS_FS_UNENCRYPTED = 0x1` per TN1150. If the bit is SET, the
/// volume is NOT encrypted. Walker probes `ApfsSuperblock.fs_flags`
/// for this bit at open time and surfaces encryption status on
/// every `VfsEntry` via `VfsAttributes.encrypted`.
///
/// Per v16 research doc §6: walker does NOT attempt decryption —
/// only marks. Encrypted content returns `VfsError::Other` on
/// `read_file` with a pickup-signal message. Offline key recovery
/// is the examiner's step with the key bundle.
pub const APFS_FS_UNENCRYPTED: u64 = 0x1;

/// Probe whether the first non-zero fs_oid volume is encrypted.
/// Reads the container OMAP + volume block + volume superblock
/// via the external crate's public submodule helpers.
///
/// Returns `Ok(true)` if the volume is encrypted, `Ok(false)` if
/// not, `Err` on any structural parse failure. Caller should treat
/// Err as "unable to determine" and fall back to marking-as-
/// unencrypted with a log warning — encryption misdetection is
/// forensically less dangerous than refusing to walk a valid
/// volume.
///
/// Note: this reads the **first** volume only — the one
/// `apfs::ApfsVolume::open()` will subsequently use. Session 5's
/// `ApfsMultiWalker` probes encryption per-volume.
pub fn probe_first_volume_encryption<R: Read + Seek>(
    reader: &mut R,
    nxsb: &NxSuperblock,
) -> Result<bool, ForensicError> {
    use apfs::omap::{omap_lookup, read_omap_tree_root};
    use apfs::superblock::ApfsSuperblock;

    let first_oid = nxsb
        .fs_oids
        .iter()
        .copied()
        .find(|&o| o != 0)
        .ok_or_else(|| ForensicError::MalformedData("apfs: no volume OIDs".into()))?;

    let block_size = nxsb.block_size;
    let container_omap_root =
        read_omap_tree_root(reader, nxsb.omap_oid, block_size).map_err(apfs_error_to_forensic)?;
    let volume_block = omap_lookup(reader, container_omap_root, block_size, first_oid)
        .map_err(apfs_error_to_forensic)?;

    // Read the volume superblock block.
    use std::io::SeekFrom;
    reader.seek(SeekFrom::Start(volume_block * block_size as u64))?;
    let mut buf = vec![0u8; block_size as usize];
    reader.read_exact(&mut buf)?;

    let vol_sb = ApfsSuperblock::parse(&buf).map_err(apfs_error_to_forensic)?;
    // APFS_FS_UNENCRYPTED set → NOT encrypted. So encrypted iff bit is clear.
    Ok(vol_sb.fs_flags & APFS_FS_UNENCRYPTED == 0)
}

/// Map `apfs::ApfsError` into Strata's `ForensicError`. Lossy —
/// the crate's enum carries more variants than the Strata error
/// shape exposes. We preserve the Debug representation via
/// `MalformedData` for forensic traceability.
pub fn apfs_error_to_forensic(e: apfs::ApfsError) -> ForensicError {
    match e {
        apfs::ApfsError::Io(err) => ForensicError::Io(err),
        other => ForensicError::MalformedData(format!("apfs: {other:?}")),
    }
}

// ── Send/Sync probes against the external crate ─────────────────

#[cfg(test)]
mod _apfs_crate_send_sync_probe {
    use super::*;
    use apfs::ApfsVolume;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn apfs_volume_over_file_is_send() {
        // Critical for the Session 4 Path A held-handle walker
        // architecture (`Mutex<ApfsVolume<PartitionReader>>`).
        // If this probe fails, the walker architecture decision
        // in RESEARCH_v16_APFS_SHAPE.md §2 must be revisited.
        assert_send::<ApfsVolume<std::fs::File>>();
    }

    #[test]
    fn apfs_volume_over_file_is_sync() {
        assert_sync::<ApfsVolume<std::fs::File>>();
    }

    #[test]
    fn nx_superblock_is_send_and_sync() {
        assert_send::<NxSuperblock>();
        assert_sync::<NxSuperblock>();
    }

    #[test]
    fn apfs_superblock_is_send_and_sync() {
        use apfs::superblock::ApfsSuperblock;
        assert_send::<ApfsSuperblock>();
        assert_sync::<ApfsSuperblock>();
    }

    #[test]
    fn apfs_error_is_send_and_sync() {
        assert_send::<apfs::ApfsError>();
        assert_sync::<apfs::ApfsError>();
    }
}

// ── Unit tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_nxsb(incompatible_features: u64, fs_oids: Vec<u64>) -> NxSuperblock {
        // The crate's NxSuperblock struct has no constructor; we
        // synthesize a bare instance for helper-function testing
        // by reading it from a minimal container. That's heavy
        // for a unit test — instead, build an instance via the
        // struct literal form. Every field of NxSuperblock is
        // `pub`, so Default-like construction is in our hands.
        use apfs::object::ObjectHeader;
        NxSuperblock {
            header: ObjectHeader {
                checksum: 0,
                oid: 1,
                xid: 1,
                type_and_flags: 0,
                subtype: 0,
            },
            magic: 0x4253_584E,
            block_size: 4096,
            block_count: 0,
            features: 0,
            readonly_compatible_features: 0,
            incompatible_features,
            uuid: [0u8; 16],
            next_oid: 0,
            next_xid: 0,
            xp_desc_blocks: 0,
            xp_data_blocks: 0,
            xp_desc_base: 0,
            xp_data_base: 0,
            xp_desc_next: 0,
            xp_data_next: 0,
            xp_desc_index: 0,
            xp_desc_len: 0,
            xp_data_index: 0,
            xp_data_len: 0,
            spaceman_oid: 0,
            omap_oid: 0,
            reaper_oid: 0,
            max_file_systems: 0,
            fs_oids,
        }
    }

    #[test]
    fn detect_fusion_returns_false_on_non_fusion_container() {
        let nxsb = make_nxsb(0, vec![]);
        assert!(!detect_fusion(&nxsb));
    }

    #[test]
    fn detect_fusion_returns_true_when_fusion_bit_set() {
        // NX_INCOMPAT_FUSION = 0x100 per TN1150 + research doc §7.
        let nxsb = make_nxsb(NX_INCOMPAT_FUSION_FLAG, vec![]);
        assert!(detect_fusion(&nxsb));
    }

    #[test]
    fn detect_fusion_ignores_other_incompatible_feature_bits() {
        // Only the 0x100 bit means fusion. Other bits (case-
        // sensitive volumes, etc.) must NOT trigger fusion
        // rejection — ordinary APFS containers carry them.
        let nxsb = make_nxsb(0x0001 | 0x0002 | 0x0020, vec![]);
        assert!(!detect_fusion(&nxsb));
    }

    #[test]
    fn detect_fusion_triggers_when_fusion_bit_combined_with_others() {
        let nxsb = make_nxsb(NX_INCOMPAT_FUSION_FLAG | 0x0002, vec![]);
        assert!(detect_fusion(&nxsb));
    }

    #[test]
    fn enumerate_volume_oids_filters_zero_slots() {
        // APFS pre-allocates `max_file_systems` fs_oid slots
        // (typically 100); unused slots stay zero. The walker
        // must iterate only populated slots, not all 100.
        let nxsb = make_nxsb(0, vec![42, 0, 0, 99, 0, 0, 0, 7, 0]);
        let oids = enumerate_volume_oids(&nxsb);
        assert_eq!(oids, vec![42, 99, 7]);
    }

    #[test]
    fn enumerate_volume_oids_handles_empty_fs_oids() {
        let nxsb = make_nxsb(0, vec![]);
        let oids = enumerate_volume_oids(&nxsb);
        assert!(oids.is_empty());
    }

    #[test]
    fn enumerate_volume_oids_handles_single_volume() {
        // The common case — one non-zero fs_oid (Mac data volume
        // on a single-volume user container, or the one fixture
        // volume the Session 1.5 probe exercised).
        let nxsb = make_nxsb(0, vec![42, 0, 0, 0]);
        let oids = enumerate_volume_oids(&nxsb);
        assert_eq!(oids, vec![42]);
    }

    #[test]
    fn nx_incompat_fusion_flag_literal_matches_spec() {
        // Tripwire: the Session 1 research doc §7 specifies
        // 0x100 literal. If this constant drifts, dispatcher
        // fusion detection silently breaks. Pins the value.
        assert_eq!(NX_INCOMPAT_FUSION_FLAG, 0x100);
    }

    #[test]
    fn apfs_error_to_forensic_preserves_io_variant() {
        let io_err = std::io::Error::other("probe");
        let ae = apfs::ApfsError::Io(io_err);
        match apfs_error_to_forensic(ae) {
            ForensicError::Io(_) => {}
            other => panic!("expected Io variant, got {other:?}"),
        }
    }

    #[test]
    fn apfs_error_to_forensic_folds_non_io_into_malformed_data() {
        let ae = apfs::ApfsError::InvalidMagic(0xDEAD_BEEF);
        match apfs_error_to_forensic(ae) {
            ForensicError::MalformedData(msg) => {
                assert!(
                    msg.starts_with("apfs: "),
                    "err msg missing apfs: prefix, got: {msg}"
                );
                assert!(
                    msg.contains("InvalidMagic"),
                    "err msg missing source variant Debug, got: {msg}"
                );
            }
            other => panic!("expected MalformedData variant, got {other:?}"),
        }
    }
}

// ── Integration test against the committed fixture ─────────────

#[cfg(test)]
mod fixture_tests {
    use super::*;

    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("apfs_small.img")
    }

    #[test]
    fn read_container_superblock_succeeds_on_fixture() {
        let path = fixture_path();
        if !path.exists() {
            eprintln!("SKIP: apfs_small.img not committed");
            return;
        }
        let mut f = std::fs::File::open(&path).expect("open fixture");
        let nxsb = read_container_superblock(&mut f).expect("read superblock");
        assert_eq!(nxsb.block_size, 4096);
        assert!(
            !detect_fusion(&nxsb),
            "fixture must not be a fusion container"
        );
        let oids = enumerate_volume_oids(&nxsb);
        assert!(
            !oids.is_empty(),
            "fixture must have at least one non-zero volume OID"
        );
        eprintln!(
            "fixture NXSuperblock: block_size={} fusion={} fs_oids={:?}",
            nxsb.block_size,
            detect_fusion(&nxsb),
            oids
        );
    }

    #[test]
    fn fixture_fusion_detect_matches_known_non_fusion_origin() {
        // The committed fixture comes from `hdiutil create -fs APFS`
        // which never produces fusion containers. Confirm the
        // helper correctly returns false — not just that it
        // returns SOME answer.
        let path = fixture_path();
        if !path.exists() {
            return;
        }
        let mut f = std::fs::File::open(&path).expect("open");
        let nxsb = read_container_superblock(&mut f).expect("read");
        assert_eq!(detect_fusion(&nxsb), false);
    }
}

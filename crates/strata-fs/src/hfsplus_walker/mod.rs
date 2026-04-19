//! FS-HFSPLUS-1 Phase B Part 2 — VFS-trait walker on top of the
//! real `read_catalog` from Phase B Part 1.
//!
//! Path A (held handle) per RESEARCH_v15_HFSPLUS_SHAPE.md §5. The
//! walker holds an `HfsPlusFilesystem` behind a `Mutex` because the
//! underlying `read_catalog` uses `&mut self` (serialized reader
//! access). `HfsPlusFilesystem` is `Send` (verified by Phase 0
//! probes in v15 Session C), so `Mutex<HfsPlusFilesystem>` is
//! `Send + Sync` — satisfying the `VirtualFilesystem` trait bound.
//!
//! No reopen-per-call pattern. That pattern was forced by
//! `ext4-view`'s `Rc<Ext4Inner>` internal; HFS+ has no such
//! constraint.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::io::{Read, Seek};
use std::sync::{Arc, Mutex};

use strata_evidence::EvidenceImage;

use crate::hfsplus::{HfsPlusCatalogEntry, HfsPlusEntryType, HfsPlusFilesystem};
use crate::ntfs_walker::PartitionReader;
use crate::vfs::{
    VfsAttributes, VfsEntry, VfsError, VfsMetadata, VfsResult, VfsSpecific, VirtualFilesystem,
};

/// Root CNID per HFS+ spec (Apple TN1150).
const ROOT_CNID: u32 = 2;

/// Names HFS+ uses internally that the walker hides by default for
/// forensic clarity. Tested against a real newfs_hfs volume: macOS
/// creates TWO private directories whose names both contain
/// `"HFS+ Private"`:
///
///   - `"\u{0}\u{0}\u{0}\u{0}HFS+ Private Data"` — hard-link data
///     store for file hard links.
///   - `".HFS+ Private Directory Data\r"` — hard-link data store
///     for directory hard links.
///
/// Walker substring-matches on `"HFS+ Private"` — a string that
/// never appears in a user-visible filename on a legitimate HFS+
/// volume. Future `--include-private` flag would expose them.
fn is_hfs_private_name(name: &str) -> bool {
    name.contains("HFS+ Private")
}

pub struct HfsPlusWalker {
    inner: Mutex<HfsPlusFilesystem>,
}

impl HfsPlusWalker {
    /// Open an HFS+ volume wrapped in a `VirtualFilesystem` walker.
    /// Accepts any partition-relative `Read + Seek + Send` reader
    /// (e.g. a `PartitionReader` over an `EvidenceImage`, or a
    /// `Cursor<Vec<u8>>` test fixture).
    pub fn open<R: Read + Seek + Send + 'static>(reader: R) -> VfsResult<Self> {
        let fs = HfsPlusFilesystem::open_reader(reader)
            .map_err(|e| VfsError::Other(format!("hfs+ open: {e}")))?;
        Ok(Self {
            inner: Mutex::new(fs),
        })
    }

    /// Open over a partition window of an `EvidenceImage`. Matches
    /// the signature the dispatcher's ext4/NTFS walkers use.
    pub fn open_on_partition(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> VfsResult<Self> {
        let sector_size = image.sector_size().max(512) as usize;
        let reader = PartitionReader::new(image, partition_offset, partition_size, sector_size);
        Self::open(reader)
    }

    /// Walk the catalog once and return every entry. Small wrapper
    /// so trait methods don't each re-lock the mutex separately for
    /// tiny queries — callers that need repeated access should
    /// cache the Vec.
    fn catalog_snapshot(&self) -> VfsResult<Vec<HfsPlusCatalogEntry>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| VfsError::Other(format!("hfs+ poisoned: {e}")))?;
        guard
            .read_catalog()
            .map_err(|e| VfsError::Other(format!("hfs+ read_catalog: {e}")))
    }
}

/// Walk the catalog entries + a target path, returning the CNID the
/// path resolves to. `/` resolves to the root CNID (2). Deeper
/// paths resolve by walking each component — O(depth × N) where N
/// is the total catalog record count. Acceptable for typical
/// forensic volumes (thousands of entries, not millions); a
/// name-indexed cache is a documented follow-on if we hit large
/// volumes.
fn resolve_path_to_cnid(entries: &[HfsPlusCatalogEntry], path: &str) -> Option<u32> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Some(ROOT_CNID);
    }
    let mut current_parent = ROOT_CNID;
    for component in trimmed.split('/') {
        // Find a folder entry whose name matches and whose parent
        // is the current CNID. Case-sensitive for now — HFS+
        // case-insensitive volumes would require folding, which is
        // a documented follow-on.
        let found = entries.iter().find(|e| {
            e.parent_cnid == current_parent
                && e.name == component
                && matches!(e.entry_type, HfsPlusEntryType::Directory)
        });
        match found {
            Some(e) => current_parent = e.cnid,
            None => return None,
        }
    }
    Some(current_parent)
}

fn entry_to_vfs(entry: &HfsPlusCatalogEntry, parent_path: &str) -> VfsEntry {
    let is_dir = matches!(entry.entry_type, HfsPlusEntryType::Directory);
    let full_path = if parent_path == "/" {
        format!("/{}", entry.name)
    } else {
        format!("{}/{}", parent_path.trim_end_matches('/'), entry.name)
    };
    VfsEntry {
        path: full_path,
        name: entry.name.clone(),
        is_directory: is_dir,
        size: 0, // Data-fork logical-size extraction is a Phase B Part 3 follow-on
        created: None,
        modified: None,
        accessed: None,
        metadata_changed: None,
        attributes: VfsAttributes {
            readonly: false,
            hidden: false,
            system: false,
            archive: false,
            compressed: false,
            encrypted: false,
            sparse: false,
            unix_mode: None,
            unix_uid: None,
            unix_gid: None,
        },
        inode_number: Some(entry.cnid as u64),
        has_alternate_streams: false, // resource fork exposure is Phase B Part 3
        fs_specific: VfsSpecific::HfsPlus {
            catalog_id: entry.cnid,
        },
    }
}

impl VirtualFilesystem for HfsPlusWalker {
    fn fs_type(&self) -> &'static str {
        "hfs+"
    }

    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let entries = self.catalog_snapshot()?;
        let target_cnid = resolve_path_to_cnid(&entries, path)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        let out: Vec<VfsEntry> = entries
            .iter()
            .filter(|e| e.parent_cnid == target_cnid && !is_hfs_private_name(&e.name))
            .map(|e| entry_to_vfs(e, path))
            .collect();
        Ok(out)
    }

    fn read_file(&self, _path: &str) -> VfsResult<Vec<u8>> {
        // Data-fork extent resolution requires fork-data storage on
        // HfsPlusCatalogEntry. Phase B Part 1 stored only the
        // record key + CNID; fork data lives at catalog record
        // offset 88..168 (data fork) and 168..248 (resource fork).
        // Phase B Part 3 surfaces those extents; Part 2 ships
        // list_dir / metadata / exists against the honest catalog
        // enumeration without content-read support.
        //
        // Pinned in tests so the limitation is explicit and a
        // future Phase B Part 3 merge must update the pinning test
        // when adding content-read support.
        Err(VfsError::Unsupported)
    }

    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> {
        let entries = self.catalog_snapshot()?;
        if path == "/" {
            return Ok(VfsMetadata {
                size: 0,
                is_directory: true,
                created: None,
                modified: None,
                accessed: None,
                attributes: VfsAttributes::default(),
            });
        }
        let trimmed = path.trim_start_matches('/');
        let (parent_path, name) = match trimmed.rsplit_once('/') {
            Some((p, n)) => (format!("/{p}"), n),
            None => ("/".to_string(), trimmed),
        };
        let parent_cnid = resolve_path_to_cnid(&entries, &parent_path)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        let found = entries
            .iter()
            .find(|e| e.parent_cnid == parent_cnid && e.name == name);
        match found {
            Some(e) => Ok(VfsMetadata {
                size: 0,
                is_directory: matches!(e.entry_type, HfsPlusEntryType::Directory),
                created: None,
                modified: None,
                accessed: None,
                attributes: VfsAttributes::default(),
            }),
            None => Err(VfsError::NotFound(path.to_string())),
        }
    }

    fn exists(&self, path: &str) -> bool {
        if path == "/" {
            return true;
        }
        self.metadata(path).is_ok()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hfsplus::HfsPlusRecordType;
    use std::io::Cursor;

    fn mk_entry(
        parent_cnid: u32,
        name: &str,
        cnid: u32,
        is_dir: bool,
    ) -> HfsPlusCatalogEntry {
        HfsPlusCatalogEntry {
            record_type: if is_dir {
                HfsPlusRecordType::CatalogFolder
            } else {
                HfsPlusRecordType::CatalogFile
            },
            cnid,
            parent_cnid,
            name: name.to_string(),
            entry_type: if is_dir {
                HfsPlusEntryType::Directory
            } else {
                HfsPlusEntryType::File
            },
        }
    }

    #[test]
    fn resolve_root_returns_root_cnid() {
        let entries: Vec<HfsPlusCatalogEntry> = Vec::new();
        assert_eq!(resolve_path_to_cnid(&entries, "/"), Some(ROOT_CNID));
        assert_eq!(resolve_path_to_cnid(&entries, ""), Some(ROOT_CNID));
    }

    #[test]
    fn resolve_walks_one_level_folder() {
        let entries = vec![
            mk_entry(ROOT_CNID, "docs", 16, true),
            mk_entry(16, "readme.txt", 17, false),
        ];
        assert_eq!(resolve_path_to_cnid(&entries, "/docs"), Some(16));
    }

    #[test]
    fn resolve_walks_two_levels() {
        let entries = vec![
            mk_entry(ROOT_CNID, "a", 10, true),
            mk_entry(10, "b", 11, true),
            mk_entry(11, "c.txt", 12, false),
        ];
        assert_eq!(resolve_path_to_cnid(&entries, "/a/b"), Some(11));
    }

    #[test]
    fn resolve_returns_none_for_missing_path() {
        let entries = vec![mk_entry(ROOT_CNID, "a", 10, true)];
        assert!(resolve_path_to_cnid(&entries, "/nope").is_none());
    }

    #[test]
    fn resolve_returns_none_when_component_is_file() {
        // Walking into a file as if it were a directory must fail.
        let entries = vec![
            mk_entry(ROOT_CNID, "f.txt", 10, false),
            mk_entry(10, "child", 11, false),
        ];
        assert!(resolve_path_to_cnid(&entries, "/f.txt/child").is_none());
    }

    #[test]
    fn entry_to_vfs_computes_full_path_from_root() {
        let e = mk_entry(ROOT_CNID, "docs", 16, true);
        let v = entry_to_vfs(&e, "/");
        assert_eq!(v.path, "/docs");
        assert_eq!(v.name, "docs");
        assert!(v.is_directory);
        assert_eq!(v.inode_number, Some(16));
    }

    #[test]
    fn entry_to_vfs_computes_full_path_from_subdir() {
        let e = mk_entry(16, "readme.txt", 17, false);
        let v = entry_to_vfs(&e, "/docs");
        assert_eq!(v.path, "/docs/readme.txt");
        assert!(!v.is_directory);
    }

    // ── End-to-end: walker on the synthesized HFS+ volume from
    // the hfsplus module's test fixture ─────────────────────────

    /// Reuse the same synth-volume pattern as the hfsplus B-tree
    /// tests but without depending on private helpers. Build a
    /// minimal HFS+ volume with one folder + one file under root.
    fn synth_hfsplus_volume_bytes() -> Vec<u8> {
        fn encode_utf16be(s: &str) -> Vec<u8> {
            let mut out = Vec::new();
            for u in s.encode_utf16() {
                out.extend_from_slice(&u.to_be_bytes());
            }
            out
        }
        fn encode_folder_record(parent_cnid: u32, name: &str, cnid: u32) -> Vec<u8> {
            let name_units: Vec<u16> = name.encode_utf16().collect();
            let key_payload_len = 4 + 2 + name_units.len() * 2;
            let mut rec = Vec::new();
            rec.extend_from_slice(&(key_payload_len as u16).to_be_bytes());
            rec.extend_from_slice(&parent_cnid.to_be_bytes());
            rec.extend_from_slice(&(name_units.len() as u16).to_be_bytes());
            rec.extend_from_slice(&encode_utf16be(name));
            if !rec.len().is_multiple_of(2) {
                rec.push(0);
            }
            let mut data = vec![0u8; 88];
            data[0..2].copy_from_slice(&1i16.to_be_bytes());
            data[8..12].copy_from_slice(&cnid.to_be_bytes());
            rec.extend_from_slice(&data);
            rec
        }
        fn encode_file_record(parent_cnid: u32, name: &str, cnid: u32) -> Vec<u8> {
            let name_units: Vec<u16> = name.encode_utf16().collect();
            let key_payload_len = 4 + 2 + name_units.len() * 2;
            let mut rec = Vec::new();
            rec.extend_from_slice(&(key_payload_len as u16).to_be_bytes());
            rec.extend_from_slice(&parent_cnid.to_be_bytes());
            rec.extend_from_slice(&(name_units.len() as u16).to_be_bytes());
            rec.extend_from_slice(&encode_utf16be(name));
            if !rec.len().is_multiple_of(2) {
                rec.push(0);
            }
            let mut data = vec![0u8; 248];
            data[0..2].copy_from_slice(&2i16.to_be_bytes());
            data[8..12].copy_from_slice(&cnid.to_be_bytes());
            rec.extend_from_slice(&data);
            rec
        }
        let block_size: u32 = 512;
        let node_size: u16 = 512;
        let num_blocks_total: u32 = 16;
        let total = (num_blocks_total as usize) * (block_size as usize);
        let mut v = vec![0u8; total];
        v[1024] = 0x48;
        v[1025] = 0x2B;
        v[1024 + 40..1024 + 44].copy_from_slice(&block_size.to_be_bytes());
        v[1024 + 44..1024 + 48].copy_from_slice(&num_blocks_total.to_be_bytes());
        let cat_logical: u64 = 1024;
        v[1024 + 272..1024 + 280].copy_from_slice(&cat_logical.to_be_bytes());
        v[1024 + 272 + 12..1024 + 272 + 16].copy_from_slice(&2u32.to_be_bytes());
        v[1024 + 272 + 16..1024 + 272 + 20].copy_from_slice(&8u32.to_be_bytes());
        v[1024 + 272 + 20..1024 + 272 + 24].copy_from_slice(&2u32.to_be_bytes());

        let hdr_node_off = 4096;
        v[hdr_node_off + 8] = 1;
        v[hdr_node_off + 10..hdr_node_off + 12].copy_from_slice(&3u16.to_be_bytes());
        let rec_off = hdr_node_off + 14;
        v[rec_off + 18..rec_off + 20].copy_from_slice(&node_size.to_be_bytes());
        v[rec_off + 2..rec_off + 6].copy_from_slice(&1u32.to_be_bytes());
        v[rec_off + 10..rec_off + 14].copy_from_slice(&1u32.to_be_bytes());
        v[rec_off + 14..rec_off + 18].copy_from_slice(&1u32.to_be_bytes());

        let leaf_off = 4608;
        v[leaf_off + 8] = 0xFF;
        v[leaf_off + 9] = 1;
        v[leaf_off + 10..leaf_off + 12].copy_from_slice(&2u16.to_be_bytes());
        let folder = encode_folder_record(ROOT_CNID, "docs", 16);
        let file = encode_file_record(ROOT_CNID, "report.txt", 17);
        let r0 = 14usize;
        let r1 = r0 + folder.len();
        let r2 = r1 + file.len();
        v[leaf_off + r0..leaf_off + r1].copy_from_slice(&folder);
        v[leaf_off + r1..leaf_off + r2].copy_from_slice(&file);
        v[leaf_off + 510..leaf_off + 512].copy_from_slice(&(r0 as u16).to_be_bytes());
        v[leaf_off + 508..leaf_off + 510].copy_from_slice(&(r1 as u16).to_be_bytes());
        v[leaf_off + 506..leaf_off + 508].copy_from_slice(&(r2 as u16).to_be_bytes());
        v
    }

    #[test]
    fn walker_opens_synthesized_volume() {
        let bytes = synth_hfsplus_volume_bytes();
        let walker = HfsPlusWalker::open(Cursor::new(bytes)).expect("open");
        assert_eq!(walker.fs_type(), "hfs+");
    }

    #[test]
    fn walker_lists_root_returns_folder_and_file() {
        let bytes = synth_hfsplus_volume_bytes();
        let walker = HfsPlusWalker::open(Cursor::new(bytes)).expect("open");
        let entries = walker.list_dir("/").expect("list_dir");
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.name == "docs" && e.is_directory));
        assert!(entries.iter().any(|e| e.name == "report.txt" && !e.is_directory));
    }

    #[test]
    fn walker_exists_returns_true_for_root() {
        let bytes = synth_hfsplus_volume_bytes();
        let walker = HfsPlusWalker::open(Cursor::new(bytes)).expect("open");
        assert!(walker.exists("/"));
    }

    #[test]
    fn walker_exists_returns_true_for_real_child() {
        let bytes = synth_hfsplus_volume_bytes();
        let walker = HfsPlusWalker::open(Cursor::new(bytes)).expect("open");
        assert!(walker.exists("/report.txt"));
        assert!(walker.exists("/docs"));
    }

    #[test]
    fn walker_exists_returns_false_for_missing_path() {
        let bytes = synth_hfsplus_volume_bytes();
        let walker = HfsPlusWalker::open(Cursor::new(bytes)).expect("open");
        assert!(!walker.exists("/nope"));
    }

    #[test]
    fn walker_metadata_reports_dir_on_folder() {
        let bytes = synth_hfsplus_volume_bytes();
        let walker = HfsPlusWalker::open(Cursor::new(bytes)).expect("open");
        let md = walker.metadata("/docs").expect("metadata");
        assert!(md.is_directory);
    }

    #[test]
    fn walker_metadata_reports_file_on_file() {
        let bytes = synth_hfsplus_volume_bytes();
        let walker = HfsPlusWalker::open(Cursor::new(bytes)).expect("open");
        let md = walker.metadata("/report.txt").expect("metadata");
        assert!(!md.is_directory);
    }

    #[test]
    fn walker_read_file_is_pinned_as_unsupported_until_phase_b_part_3() {
        // v15 Session D tripwire — read_file returns Unsupported
        // because fork-data extraction isn't shipped yet. Any
        // future merge that implements data-fork reading must flip
        // this test at the same time. Convention carried from
        // Sessions B/C.
        let bytes = synth_hfsplus_volume_bytes();
        let walker = HfsPlusWalker::open(Cursor::new(bytes)).expect("open");
        match walker.read_file("/report.txt") {
            Err(VfsError::Unsupported) => {}
            other => panic!(
                "read_file must return Unsupported until Phase B Part 3; got {other:?}"
            ),
        }
    }

    #[test]
    fn walker_list_dir_returns_not_found_for_bad_path() {
        let bytes = synth_hfsplus_volume_bytes();
        let walker = HfsPlusWalker::open(Cursor::new(bytes)).expect("open");
        match walker.list_dir("/nope") {
            Err(VfsError::NotFound(p)) => assert_eq!(p, "/nope"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn walker_satisfies_send_and_sync() {
        // Path A verified: HfsPlusWalker must be Send + Sync to
        // satisfy the VirtualFilesystem trait bound.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<HfsPlusWalker>();
        assert_sync::<HfsPlusWalker>();
    }
}

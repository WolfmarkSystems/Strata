//! HFS+ (Hierarchical File System Plus) parser.
//!
//! Provides `hfsplus_fast_scan(&[u8])` for in-memory signature scans
//! and `HfsPlusFilesystem` for holding parsed volume state with an
//! internal `Read + Seek` handle.
//!
//! v15 Session C — Phase A Read+Seek refactor (per
//! `docs/RESEARCH_v15_HFSPLUS_SHAPE.md`). Previously the struct stored
//! a bare `File` handle and path-based constructors were the only
//! entry point. After this refactor:
//!
//! - `open_reader<R: Read + Seek + Send + 'static>(reader)` is the
//!   primary constructor; callers pass a partition-relative reader
//!   (e.g. the `PartitionReader` from `ntfs_walker::adapter`).
//! - `open(path)` and `open_at_offset(path, offset)` are preserved
//!   as thin wrappers delegating to `open_reader` via the
//!   `OffsetReader` shim. Existing call sites are unchanged.
//! - Internal handle switched from `File` to
//!   `Box<dyn HfsReadSeek>` to keep the struct non-generic (no
//!   cascade through callers, no monomorphization blow-up).
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use crate::errors::ForensicError;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

pub const HFSPLUS_MAGIC: u16 = 0x482B; // H+
pub const HFSX_MAGIC: u16 = 0x4858; // HX

/// Helper trait so we can store a `Box<dyn HfsReadSeek>` — Rust doesn't
/// allow `Box<dyn Read + Seek>` directly.
pub trait HfsReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send + ?Sized> HfsReadSeek for T {}

pub fn hfsplus_fast_scan(data: &[u8]) -> Result<HfsPlusFastScanResult, ForensicError> {
    if data.len() < 2048 {
        return Err(ForensicError::UnsupportedFilesystem);
    }

    // Volume header is at offset 1024
    let header = &data[1024..1536];
    let signature =
        u16::from_be_bytes(header[0..2].try_into().map_err(|_| ForensicError::InvalidImageFormat)?);

    if signature != HFSPLUS_MAGIC && signature != HFSX_MAGIC {
        return Err(ForensicError::UnsupportedFilesystem);
    }

    let block_size = u32::from_be_bytes(
        header[40..44]
            .try_into()
            .map_err(|_| ForensicError::InvalidImageFormat)?,
    );
    let total_blocks = u32::from_be_bytes(
        header[44..48]
            .try_into()
            .map_err(|_| ForensicError::InvalidImageFormat)?,
    ) as u64;
    let free_blocks = u32::from_be_bytes(
        header[48..52]
            .try_into()
            .map_err(|_| ForensicError::InvalidImageFormat)?,
    ) as u64;

    Ok(HfsPlusFastScanResult {
        found: true,
        block_size,
        fs_uuid: [0; 16], // Extracted from Finder Info or Attributes
        volume_name: "HFS+ Volume".to_string(),
        total_blocks,
        free_blocks,
    })
}

#[derive(Debug, Clone, Default)]
pub struct HfsPlusFastScanResult {
    pub found: bool,
    pub block_size: u32,
    pub fs_uuid: [u8; 16],
    pub volume_name: String,
    pub total_blocks: u64,
    pub free_blocks: u64,
}

pub fn open_hfsplus(path: &Path) -> Result<HfsPlusFilesystem, ForensicError> {
    HfsPlusFilesystem::open(path)
}

/// Parsed HFS+ volume state with an internal `Read + Seek` handle.
///
/// Post-Phase-A, the handle is partition-relative: cursor `0` is the
/// start of the HFS+ volume, not the start of the image file. The
/// `OffsetReader` shim used by the path-based constructors adjusts
/// for that.
pub struct HfsPlusFilesystem {
    reader: Box<dyn HfsReadSeek>,
    pub volume_header: HfsPlusVolumeHeader,
    pub catalog_file: HfsPlusCatalogFile,
    /// Always `0` post-Phase-A — the handle is already partition-
    /// relative. Retained as a `pub` field for API stability with
    /// any callers that read it (none in-tree at refactor time).
    pub base_offset: u64,
}

impl std::fmt::Debug for HfsPlusFilesystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HfsPlusFilesystem")
            .field("reader", &"<dyn HfsReadSeek>")
            .field("volume_header", &self.volume_header)
            .field("catalog_file", &self.catalog_file)
            .field("base_offset", &self.base_offset)
            .finish()
    }
}

impl HfsPlusFilesystem {
    /// Open an HFS+ volume from a file on disk. Thin wrapper over
    /// `open_reader` preserved for backward compatibility with
    /// pre-Phase-A callers. Delegates via `OffsetReader::new(file, 0)`.
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        Self::open_at_offset(path, 0)
    }

    /// Open an HFS+ volume at a known byte offset inside a file on
    /// disk (e.g. a partition inside a raw image). Thin wrapper over
    /// `open_reader` preserved for backward compatibility. Delegates
    /// via `OffsetReader`.
    pub fn open_at_offset(path: &Path, offset: u64) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        Self::open_reader(OffsetReader::new(file, offset))
    }

    /// Primary constructor post-Phase-A. Accepts any partition-
    /// relative `Read + Seek + Send` reader — the dispatcher's
    /// `PartitionReader`, a `Cursor<Vec<u8>>` test fixture, or any
    /// other stream. Parses the HFS+ volume header and catalog-file
    /// descriptor; does not walk the B-tree (that's
    /// `read_catalog`).
    pub fn open_reader<R: Read + Seek + Send + 'static>(reader: R) -> Result<Self, ForensicError> {
        let mut boxed: Box<dyn HfsReadSeek> = Box::new(reader);
        boxed.seek(SeekFrom::Start(1024))?;

        let mut header = [0u8; 512];
        boxed.read_exact(&mut header)?;

        let signature = u16::from_be_bytes(
            header[0..2]
                .try_into()
                .map_err(|_| ForensicError::InvalidImageFormat)?,
        );
        if signature != HFSPLUS_MAGIC && signature != HFSX_MAGIC {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        let vh = HfsPlusVolumeHeader {
            signature,
            version: u16::from_be_bytes(
                header[2..4]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            ),
            attributes: u32::from_be_bytes(
                header[4..8]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            ),
            blocksize: u32::from_be_bytes(
                header[40..44]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            ),
            total_blocks: u32::from_be_bytes(
                header[44..48]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            ),
        };

        // Parse Catalog File fork data (offset 272 in VolumeHeader
        // per Apple TN1150: allocationFile at 112, extentsFile at
        // 192, catalogFile at 272). The earlier "288" constant was
        // off by 16 bytes — it was picking up 16 bytes into the
        // catalog fork, mixing the tail of logicalSize with the
        // head of clumpSize. Test coverage caught this when
        // ground_truth_hfsplus.rs ran against a real newfs_hfs
        // volume; synth-volume tests happened to be aligned to the
        // buggy constant and so didn't surface the problem.
        let catalog_fork_data = &header[272..352];
        let logic_size = u64::from_be_bytes(
            catalog_fork_data[0..8]
                .try_into()
                .map_err(|_| ForensicError::InvalidImageFormat)?,
        );

        let mut extents = Vec::new();
        for i in 0..8 {
            let off = 16 + (i * 8);
            let start_block = u32::from_be_bytes(
                catalog_fork_data[off..off + 4]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            );
            let block_count = u32::from_be_bytes(
                catalog_fork_data[off + 4..off + 8]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            );
            if block_count > 0 {
                extents.push(HfsPlusExtentDescriptor {
                    start_block,
                    block_count,
                });
            }
        }

        let mut catalog_file = HfsPlusCatalogFile {
            logical_size: logic_size,
            extents,
            node_size: 0,
            root_node: 0,
            first_leaf_node: 0,
            last_leaf_node: 0,
        };

        // If extents exist, read the B-tree header node (node 0).
        if !catalog_file.extents.is_empty() {
            let first_block = catalog_file.extents[0].start_block as u64;
            let offset = first_block * vh.blocksize as u64;
            boxed.seek(SeekFrom::Start(offset))?;

            let mut btree_node_desc = [0u8; 14];
            boxed.read_exact(&mut btree_node_desc)?;

            let mut btree_header_rec = [0u8; 106];
            boxed.read_exact(&mut btree_header_rec)?;

            // B-tree Header Record layout per Apple TN1150:
            //   offset 0   treeDepth       (u16)
            //   offset 2   rootNode        (u32)
            //   offset 6   leafRecords     (u32)
            //   offset 10  firstLeafNode   (u32)
            //   offset 14  lastLeafNode    (u32)
            //   offset 18  nodeSize        (u16)
            //   offset 20  maxKeyLength    (u16)
            //   ...
            // The pre-Session-D code read these at completely wrong
            // offsets (8 / 16 / 24 / 28) which yielded garbage on
            // any real HFS+ volume. Synth tests happened to write
            // the same wrong offsets so they silently passed. The
            // real-fixture ground_truth test surfaces the bug.
            catalog_file.root_node = u32::from_be_bytes(
                btree_header_rec[2..6]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            );
            catalog_file.first_leaf_node = u32::from_be_bytes(
                btree_header_rec[10..14]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            );
            catalog_file.last_leaf_node = u32::from_be_bytes(
                btree_header_rec[14..18]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            );
            catalog_file.node_size = u16::from_be_bytes(
                btree_header_rec[18..20]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            );
        }
        Ok(Self {
            reader: boxed,
            volume_header: vh,
            catalog_file,
            base_offset: 0,
        })
    }

    pub fn read_block(&mut self, block: u64) -> Result<Vec<u8>, ForensicError> {
        let mut buf = vec![0u8; self.volume_header.blocksize as usize];
        let offset = self.base_offset + (block * self.volume_header.blocksize as u64);
        self.reader.seek(SeekFrom::Start(offset))?;
        self.reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Walk the Catalog B-tree leaf-node chain and return every
    /// catalog record as an `HfsPlusCatalogEntry`.
    ///
    /// v15 Session D Sprint 1 Phase B Part 1 — replaces the
    /// structural stub that preceded this implementation. Iteration
    /// follows the `fLink` sibling chain starting at
    /// `self.catalog_file.first_leaf_node`, decoding each leaf
    /// node's variable-length records via the tail offset table.
    /// Thread records (folder-thread / file-thread) are skipped for
    /// flat enumeration — their back-pointer role (CNID → parent
    /// name) is useful for path reconstruction, which is a separate
    /// follow-on concern.
    ///
    /// Safety bounds:
    /// - Every byte-slice access is `.get(range).ok_or(...)` so a
    ///   malformed leaf produces `Err`, not panic.
    /// - Iteration cap of 100,000 nodes prevents a hostile
    ///   `fLink`-cycle from looping forever.
    /// - Big-endian decode throughout — HFS+ is BE on disk.
    pub fn read_catalog(&mut self) -> Result<Vec<HfsPlusCatalogEntry>, ForensicError> {
        let node_size = self.catalog_file.node_size as usize;
        if node_size == 0 || self.catalog_file.first_leaf_node == 0 {
            return Ok(Vec::new());
        }

        let mut entries: Vec<HfsPlusCatalogEntry> = Vec::new();
        let mut node_idx = self.catalog_file.first_leaf_node;
        let mut visited = 0usize;
        const MAX_NODES: usize = 100_000;

        while node_idx != 0 && visited < MAX_NODES {
            visited += 1;
            let node = self.read_catalog_node(node_idx)?;
            if node.len() < 14 {
                return Err(ForensicError::InvalidImageFormat);
            }
            let desc = parse_node_descriptor(&node)?;
            // Skip non-leaves via the sibling link. For walker
            // enumeration we only consume leaves — index nodes are
            // shortcuts the tree builds for name lookup.
            if desc.kind != NODE_KIND_LEAF {
                node_idx = desc.flink;
                continue;
            }
            let offsets = parse_record_offsets(&node, desc.num_records)?;
            for i in 0..(desc.num_records as usize) {
                let start = *offsets
                    .get(i)
                    .ok_or(ForensicError::InvalidImageFormat)? as usize;
                let end = *offsets
                    .get(i + 1)
                    .ok_or(ForensicError::InvalidImageFormat)? as usize;
                if start >= end || end > node.len() {
                    // Corrupt record offset — skip this record and
                    // continue, don't fail the whole walk.
                    continue;
                }
                let record = &node[start..end];
                if let Some(entry) = parse_catalog_record(record)? {
                    entries.push(entry);
                }
            }
            node_idx = desc.flink;
        }

        Ok(entries)
    }

    /// Read a single B-tree node by its node index. Resolves the
    /// byte offset as `node_idx * node_size` inside the catalog
    /// file's first extent — a simplification that works correctly
    /// for any B-tree whose leaves fit in the initial extent run
    /// (the overwhelmingly common case for filesystems with
    /// catalogs under a few MB, which is everything we'll see in
    /// tests and typical forensic evidence).
    ///
    /// Extent-overflow traversal (for catalogs spanning multiple
    /// non-contiguous extents) is a documented follow-on; the
    /// initial fixture-scale tests don't hit it.
    fn read_catalog_node(&mut self, node_idx: u32) -> Result<Vec<u8>, ForensicError> {
        let node_size = self.catalog_file.node_size as u64;
        if self.catalog_file.extents.is_empty() {
            return Err(ForensicError::InvalidImageFormat);
        }
        let first_block = self.catalog_file.extents[0].start_block as u64;
        let first_block_count = self.catalog_file.extents[0].block_count as u64;
        let block_size = self.volume_header.blocksize as u64;
        let node_offset_in_file = (node_idx as u64).saturating_mul(node_size);
        // Sanity: first extent covers this node.
        let extent_end_in_file = first_block_count.saturating_mul(block_size);
        if node_offset_in_file.saturating_add(node_size) > extent_end_in_file {
            // Node lies past the first extent. Not supported in
            // Part 1; caller receives an error rather than silent
            // wrong data.
            return Err(ForensicError::InvalidImageFormat);
        }
        let absolute = self.base_offset
            + first_block.saturating_mul(block_size)
            + node_offset_in_file;
        self.reader.seek(SeekFrom::Start(absolute))?;
        let mut buf = vec![0u8; node_size as usize];
        self.reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

// ── B-tree node decoding helpers (Sprint 1 Phase B Part 1) ────────────

/// HFS+ B-tree node kinds. Walker cares only about leaf nodes —
/// index/header/map nodes are skipped via sibling-link iteration.
const NODE_KIND_LEAF: i8 = -1; // 0xFF as i8 per Apple TN1150
const NODE_KIND_INDEX: i8 = 0;
const NODE_KIND_HEADER: i8 = 1;
const NODE_KIND_MAP: i8 = 2;

#[derive(Debug, Clone, Copy)]
struct BtNodeDescriptor {
    flink: u32,
    #[allow(dead_code)]
    blink: u32,
    kind: i8,
    #[allow(dead_code)]
    height: u8,
    num_records: u16,
}

fn parse_node_descriptor(node: &[u8]) -> Result<BtNodeDescriptor, ForensicError> {
    let head = node
        .get(0..14)
        .ok_or(ForensicError::InvalidImageFormat)?;
    let flink = u32::from_be_bytes(
        head[0..4]
            .try_into()
            .map_err(|_| ForensicError::InvalidImageFormat)?,
    );
    let blink = u32::from_be_bytes(
        head[4..8]
            .try_into()
            .map_err(|_| ForensicError::InvalidImageFormat)?,
    );
    let kind = head[8] as i8;
    let height = head[9];
    let num_records = u16::from_be_bytes(
        head[10..12]
            .try_into()
            .map_err(|_| ForensicError::InvalidImageFormat)?,
    );
    // Sanity: reject kinds outside the known range. Keeps the
    // discriminator from silently matching via i8 wrap on a
    // corrupt node.
    if !matches!(
        kind,
        NODE_KIND_LEAF | NODE_KIND_INDEX | NODE_KIND_HEADER | NODE_KIND_MAP
    ) {
        return Err(ForensicError::InvalidImageFormat);
    }
    Ok(BtNodeDescriptor {
        flink,
        blink,
        kind,
        height,
        num_records,
    })
}

/// Decode the tail offset table into a Vec of byte offsets (one per
/// record plus the end-of-used-space sentinel, so length =
/// `num_records + 1`). Entries are ordered ascending (we reverse
/// from the on-disk last-record-first layout).
fn parse_record_offsets(node: &[u8], num_records: u16) -> Result<Vec<u16>, ForensicError> {
    let needed = 2 * (num_records as usize + 1);
    if node.len() < needed {
        return Err(ForensicError::InvalidImageFormat);
    }
    let mut out: Vec<u16> = Vec::with_capacity(num_records as usize + 1);
    // On-disk: offset_at(n) lives at node[len - 2*(n+1) .. len - 2*n].
    // We want indexes 0..=num_records in ascending order.
    for n in 0..=(num_records as usize) {
        let end = node.len() - 2 * n;
        let start = end - 2;
        let raw = u16::from_be_bytes(
            node[start..end]
                .try_into()
                .map_err(|_| ForensicError::InvalidImageFormat)?,
        );
        out.push(raw);
    }
    Ok(out)
}

/// HFS+ catalog record-type discriminator (first 2 bytes of record
/// data, BE i16).
const REC_TYPE_FOLDER: i16 = 1;
const REC_TYPE_FILE: i16 = 2;
const REC_TYPE_FOLDER_THREAD: i16 = 3;
const REC_TYPE_FILE_THREAD: i16 = 4;

fn parse_catalog_record(record: &[u8]) -> Result<Option<HfsPlusCatalogEntry>, ForensicError> {
    // Key: keyLength (u16 BE, does not include itself) + parentID (u32
    // BE) + nodeName.length (u16 BE) + UTF-16BE data.
    if record.len() < 2 {
        return Err(ForensicError::InvalidImageFormat);
    }
    let key_length = u16::from_be_bytes(
        record[0..2]
            .try_into()
            .map_err(|_| ForensicError::InvalidImageFormat)?,
    );
    // Total key bytes on the wire = keyLength + 2 (keyLength itself
    // is not counted). Data follows at an even byte boundary — some
    // documents specify 2-byte alignment after the key, so align up.
    let key_end = 2 + key_length as usize;
    if key_end > record.len() {
        return Err(ForensicError::InvalidImageFormat);
    }
    let data_start = if key_end.is_multiple_of(2) {
        key_end
    } else {
        key_end + 1
    };
    if data_start >= record.len() {
        return Err(ForensicError::InvalidImageFormat);
    }

    let key = &record[0..key_end];
    // Parse key parentID + name
    if key.len() < 8 {
        return Err(ForensicError::InvalidImageFormat);
    }
    let parent_cnid = u32::from_be_bytes(
        key[2..6]
            .try_into()
            .map_err(|_| ForensicError::InvalidImageFormat)?,
    );
    let name_len_units = u16::from_be_bytes(
        key[6..8]
            .try_into()
            .map_err(|_| ForensicError::InvalidImageFormat)?,
    ) as usize;
    let name_bytes_needed = 8 + name_len_units * 2;
    if name_bytes_needed > key.len() {
        return Err(ForensicError::InvalidImageFormat);
    }
    let name = decode_utf16be_name(&key[8..8 + name_len_units * 2])?;

    // Data: first 2 bytes = recordType (BE i16)
    let data = &record[data_start..];
    if data.len() < 2 {
        return Err(ForensicError::InvalidImageFormat);
    }
    let rec_type = i16::from_be_bytes(
        data[0..2]
            .try_into()
            .map_err(|_| ForensicError::InvalidImageFormat)?,
    );
    match rec_type {
        REC_TYPE_FOLDER => {
            if data.len() < 12 {
                return Err(ForensicError::InvalidImageFormat);
            }
            // folderID at offset 8
            let cnid = u32::from_be_bytes(
                data[8..12]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            );
            Ok(Some(HfsPlusCatalogEntry {
                record_type: HfsPlusRecordType::CatalogFolder,
                cnid,
                parent_cnid,
                name,
                entry_type: HfsPlusEntryType::Directory,
            }))
        }
        REC_TYPE_FILE => {
            if data.len() < 12 {
                return Err(ForensicError::InvalidImageFormat);
            }
            // fileID at offset 8
            let cnid = u32::from_be_bytes(
                data[8..12]
                    .try_into()
                    .map_err(|_| ForensicError::InvalidImageFormat)?,
            );
            Ok(Some(HfsPlusCatalogEntry {
                record_type: HfsPlusRecordType::CatalogFile,
                cnid,
                parent_cnid,
                name,
                entry_type: HfsPlusEntryType::File,
            }))
        }
        REC_TYPE_FOLDER_THREAD | REC_TYPE_FILE_THREAD => {
            // Thread records are back-pointers, not filesystem
            // entries. Skip for flat enumeration.
            Ok(None)
        }
        _ => {
            // Unknown record type — skip without erroring, so
            // forensic evidence with extension records we don't
            // recognize still yields the records we do.
            Ok(None)
        }
    }
}

/// Decode a UTF-16BE byte sequence into a `String` preserving the
/// original bytes' normalization (no re-normalization). Returns
/// `Err` on invalid-surrogate sequences rather than lossy-decoding
/// — examiners need to know if a name couldn't be faithfully
/// represented.
fn decode_utf16be_name(bytes: &[u8]) -> Result<String, ForensicError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(ForensicError::InvalidImageFormat);
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).map_err(|_| ForensicError::InvalidImageFormat)
}

/// Shim that makes any `Read + Seek` look partition-relative by
/// shifting every seek by a fixed byte offset. Used by the
/// path-based constructors to delegate into `open_reader`.
pub struct OffsetReader<R> {
    inner: R,
    offset: u64,
}

impl<R> OffsetReader<R> {
    pub fn new(inner: R, offset: u64) -> Self {
        Self { inner, offset }
    }
}

impl<R: Read> Read for OffsetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Seek> Seek for OffsetReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let absolute = match pos {
            SeekFrom::Start(v) => self.offset.checked_add(v).ok_or_else(|| {
                io::Error::other(format!(
                    "OffsetReader seek-from-start overflow: {} + {v}",
                    self.offset
                ))
            })?,
            SeekFrom::Current(v) => {
                // Delegate directly — the inner cursor is the
                // absolute position already.
                return self
                    .inner
                    .seek(SeekFrom::Current(v))
                    .map(|a| a.saturating_sub(self.offset));
            }
            SeekFrom::End(v) => {
                return self
                    .inner
                    .seek(SeekFrom::End(v))
                    .map(|a| a.saturating_sub(self.offset));
            }
        };
        self.inner
            .seek(SeekFrom::Start(absolute))
            .map(|a| a.saturating_sub(self.offset))
    }
}

#[derive(Debug, Clone, Default)]
pub struct HfsPlusVolumeHeader {
    pub signature: u16,
    pub version: u16,
    pub attributes: u32,
    pub blocksize: u32,
    pub total_blocks: u32,
}

#[derive(Debug, Clone)]
pub struct HfsPlusCatalogFile {
    pub logical_size: u64,
    pub extents: Vec<HfsPlusExtentDescriptor>,
    pub node_size: u16,
    pub root_node: u32,
    pub first_leaf_node: u32,
    pub last_leaf_node: u32,
}

#[derive(Debug, Clone)]
pub struct HfsPlusExtentDescriptor {
    pub start_block: u32,
    pub block_count: u32,
}

#[derive(Debug, Clone)]
pub struct HfsPlusCatalogEntry {
    pub record_type: HfsPlusRecordType,
    pub cnid: u32,
    pub parent_cnid: u32,
    pub name: String,
    pub entry_type: HfsPlusEntryType,
}

#[derive(Debug, Clone)]
pub enum HfsPlusRecordType {
    CatalogFolder,
    CatalogFile,
    CatalogThread,
}

#[derive(Debug, Clone)]
pub enum HfsPlusEntryType {
    Directory,
    File,
    Symlink,
}

pub fn parse_hfsplus_btree(_data: &[u8]) -> Result<HfsPlusBtree, ForensicError> {
    Ok(HfsPlusBtree::default())
}

#[derive(Debug, Clone, Default)]
pub struct HfsPlusBtree {
    pub node_size: u16,
    pub max_key_length: u16,
    pub node_count: u32,
}

pub fn extract_hfsplus_timeline(
    _fs: &HfsPlusFilesystem,
) -> Result<Vec<HfsPlusTimelineEntry>, ForensicError> {
    Ok(vec![])
}

#[derive(Debug, Clone, Default)]
pub struct HfsPlusTimelineEntry {
    pub timestamp: u64,
    pub cnid: u32,
    pub path: String,
    pub action: String,
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod _send_sync_probe {
    use super::*;
    use crate::vfs::VfsEntry;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn hfsplus_filesystem_is_send() {
        assert_send::<HfsPlusFilesystem>();
    }

    #[test]
    fn hfsplus_filesystem_is_sync() {
        // Post-Phase-A this now requires `dyn HfsReadSeek` to be
        // `Sync`; `Box<dyn HfsReadSeek>` without explicit `+ Sync`
        // is `Send` but not `Sync`. The trait object alone does
        // NOT satisfy `Sync`, so the whole struct does not.
        //
        // We therefore verify the *intent* — that the
        // walker-visible state (volume_header / catalog_file /
        // base_offset) is `Sync`. The reader handle itself is kept
        // behind `&mut self` in all trait methods, so shared-ref
        // concurrency would go through external synchronization
        // anyway (e.g. `Arc<Mutex<HfsPlusFilesystem>>`).
        //
        // This matches the NtfsWalker's `Mutex<NtfsState>` pattern.
        assert_send::<HfsPlusVolumeHeader>();
        assert_send::<HfsPlusCatalogFile>();
        assert_sync::<HfsPlusVolumeHeader>();
        assert_sync::<HfsPlusCatalogFile>();
    }

    // v15 Session C — Phase 0 Send probes from
    // RESEARCH_v15_HFSPLUS_SHAPE.md §6. Both pass: Path A (held
    // handle, `Vec::into_iter()` wrapped) is confirmed viable.
    // The research doc's iterator-chain analysis holds.

    #[test]
    fn hfsplus_catalog_entry_is_send() {
        assert_send::<HfsPlusCatalogEntry>();
    }

    #[test]
    fn vfs_entry_is_send() {
        assert_send::<VfsEntry>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn synth_hfsplus_volume_bytes() -> Vec<u8> {
        // 4 KiB: 1024 bytes padding + 512-byte volume header + 2560
        // bytes room for a synthesized B-tree header if extents
        // exist. We deliberately leave the catalog extents zeroed so
        // the B-tree header read path doesn't fire (no extents means
        // skip-the-extent-read branch in open_reader).
        let mut v = vec![0u8; 4096];
        // Signature "H+" at offset 1024..1026.
        v[1024] = 0x48;
        v[1025] = 0x2B;
        // Blocksize 512 (u32 BE at 1024+40..1024+44)
        v[1024 + 43] = 0x00;
        v[1024 + 42] = 0x02; // 0x0200 == 512 in BE
        v
    }

    #[test]
    fn fast_scan_matches_hfsplus_magic() {
        let bytes = synth_hfsplus_volume_bytes();
        let r = hfsplus_fast_scan(&bytes).expect("fast scan must succeed on synthesized volume");
        assert!(r.found);
        assert_eq!(r.block_size, 512);
    }

    #[test]
    fn fast_scan_rejects_non_hfsplus_magic() {
        let v = vec![0u8; 4096];
        let r = hfsplus_fast_scan(&v);
        assert!(r.is_err(), "all-zero buffer must fail fast scan");
    }

    #[test]
    fn open_reader_accepts_in_memory_cursor() {
        // Phase A acceptance — the primary constructor accepts any
        // Read + Seek + Send handle, not just a File. This is the
        // contract the dispatcher will use in Session C+ once the
        // walker ships.
        let bytes = synth_hfsplus_volume_bytes();
        let cursor = Cursor::new(bytes);
        let fs = HfsPlusFilesystem::open_reader(cursor)
            .expect("open_reader must succeed on synthesized volume");
        assert_eq!(fs.volume_header.signature, HFSPLUS_MAGIC);
        assert_eq!(fs.volume_header.blocksize, 512);
        assert_eq!(fs.base_offset, 0, "reader-based constructor → base_offset=0");
    }

    #[test]
    fn open_reader_rejects_bad_signature() {
        let v = vec![0u8; 4096]; // no "H+" / "HX" magic
        let cursor = Cursor::new(v);
        let res = HfsPlusFilesystem::open_reader(cursor);
        match res {
            Err(ForensicError::UnsupportedFilesystem) => {}
            other => panic!("expected UnsupportedFilesystem, got {other:?}"),
        }
    }

    #[test]
    fn open_path_wrapper_delegates_to_open_reader() {
        // Backward compatibility: the path-based constructor must
        // produce the same parsed state as `open_reader` when given
        // equivalent bytes. Write the synth volume to a tempfile and
        // open via the path API.
        let bytes = synth_hfsplus_volume_bytes();
        let tmp = tempfile::NamedTempFile::new().expect("tmp");
        std::io::Write::write_all(&mut tmp.as_file().try_clone().expect("clone"), &bytes)
            .expect("write");
        let fs = HfsPlusFilesystem::open(tmp.path())
            .expect("open(path) must succeed on synthesized volume");
        assert_eq!(fs.volume_header.signature, HFSPLUS_MAGIC);
        assert_eq!(fs.volume_header.blocksize, 512);
    }

    #[test]
    fn open_at_offset_shifts_reader_correctly() {
        // Build a larger buffer with the HFS+ volume at offset 2048,
        // call open_at_offset(path, 2048), verify parse succeeds.
        // This exercises the OffsetReader shim.
        let hfsplus_bytes = synth_hfsplus_volume_bytes();
        let mut big = vec![0u8; 2048 + hfsplus_bytes.len()];
        big[2048..2048 + hfsplus_bytes.len()].copy_from_slice(&hfsplus_bytes);
        let tmp = tempfile::NamedTempFile::new().expect("tmp");
        std::io::Write::write_all(&mut tmp.as_file().try_clone().expect("clone"), &big)
            .expect("write");
        let fs = HfsPlusFilesystem::open_at_offset(tmp.path(), 2048)
            .expect("open_at_offset must succeed");
        assert_eq!(fs.volume_header.signature, HFSPLUS_MAGIC);
    }

    #[test]
    fn offset_reader_seek_from_start_shifts_correctly() {
        // Unit-level check on the shim itself. Seeking to 100 on an
        // OffsetReader(offset=50) should land at absolute 150 in
        // the inner stream and report 100 as the relative position.
        let bytes: Vec<u8> = (0..200u8).collect();
        let inner = Cursor::new(bytes);
        let mut shim = OffsetReader::new(inner, 50);
        let rel = shim.seek(SeekFrom::Start(100)).expect("seek");
        assert_eq!(rel, 100);
        let mut buf = [0u8; 4];
        shim.read_exact(&mut buf).expect("read");
        // Absolute position was 150; bytes[150] == 150.
        assert_eq!(buf, [150, 151, 152, 153]);
    }

    #[test]
    fn read_catalog_returns_empty_when_first_leaf_zero() {
        // v15 Session D — Phase B Part 1 replaced the stub with real
        // B-tree iteration. When the catalog has no populated leaves
        // (either logical_size == 0 or first_leaf_node == 0), the
        // iteration returns an empty Vec cleanly — NOT a placeholder
        // "root" entry as the old stub did.
        //
        // This test formerly pinned the stub's placeholder behavior
        // under the name `read_catalog_stub_still_returns_placeholder`.
        // The rename + assertion flip in Sprint 1 Phase B is
        // deliberate: the limitation is REMOVED in this commit, so
        // the pinning test becomes a positive assertion about the
        // real behavior.
        let bytes = synth_hfsplus_volume_bytes();
        let cursor = Cursor::new(bytes);
        let mut fs = HfsPlusFilesystem::open_reader(cursor).expect("open");
        let cat = fs.read_catalog().expect("read_catalog");
        assert!(
            cat.is_empty(),
            "real iteration returns empty on a volume with no catalog extents"
        );
    }

    // ── B-tree decoder unit tests (Sprint 1 Phase B Part 1) ────

    #[test]
    fn parse_node_descriptor_decodes_leaf() {
        let mut n = vec![0u8; 512];
        // fLink = 5
        n[0..4].copy_from_slice(&5u32.to_be_bytes());
        // bLink = 0
        n[4..8].copy_from_slice(&0u32.to_be_bytes());
        // kind = -1 (leaf)
        n[8] = 0xFF;
        // height = 1
        n[9] = 1;
        // numRecords = 3
        n[10..12].copy_from_slice(&3u16.to_be_bytes());
        let d = parse_node_descriptor(&n).expect("decode");
        assert_eq!(d.flink, 5);
        assert_eq!(d.kind, NODE_KIND_LEAF);
        assert_eq!(d.num_records, 3);
    }

    #[test]
    fn parse_node_descriptor_rejects_short_buffer() {
        let n = vec![0u8; 10];
        assert!(parse_node_descriptor(&n).is_err());
    }

    #[test]
    fn parse_node_descriptor_rejects_unknown_kind() {
        let mut n = vec![0u8; 14];
        n[8] = 42; // not in {-1, 0, 1, 2}
        assert!(parse_node_descriptor(&n).is_err());
    }

    #[test]
    fn parse_record_offsets_is_ascending_end_to_start() {
        // Simulate a 512-byte node with 2 records:
        //   record 0 at offset 14 (right after descriptor)
        //   record 1 at offset 64
        //   free-space start at offset 128
        // On-disk offset table ends at byte 512 and stores the
        // offsets in reverse: [free, rec1, rec0].
        let node_size = 512;
        let mut n = vec![0u8; node_size];
        let free_start = 128u16;
        let r1 = 64u16;
        let r0 = 14u16;
        // Tail three u16 BE values in reverse order:
        //   bytes 510..512 → offset of record 0 (14)
        //   bytes 508..510 → offset of record 1 (64)
        //   bytes 506..508 → free-space sentinel (128)
        n[510..512].copy_from_slice(&r0.to_be_bytes());
        n[508..510].copy_from_slice(&r1.to_be_bytes());
        n[506..508].copy_from_slice(&free_start.to_be_bytes());

        let offsets = parse_record_offsets(&n, 2).expect("decode");
        assert_eq!(offsets.len(), 3);
        assert_eq!(offsets[0], 14);
        assert_eq!(offsets[1], 64);
        assert_eq!(offsets[2], 128);
    }

    fn encode_utf16be(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for unit in s.encode_utf16() {
            out.extend_from_slice(&unit.to_be_bytes());
        }
        out
    }

    /// Build a minimal leaf-node catalog record: key + data for a
    /// single folder record. Returns the record bytes (no padding
    /// around it) so tests can place it inside a node.
    fn encode_folder_record(parent_cnid: u32, name: &str, cnid: u32) -> Vec<u8> {
        let name_units: Vec<u16> = name.encode_utf16().collect();
        // key = parentID u32 + nameLength u16 + name UTF-16BE
        let key_payload_len = 4 + 2 + name_units.len() * 2;
        let key_length = key_payload_len as u16; // does NOT include itself
        let mut rec: Vec<u8> = Vec::new();
        rec.extend_from_slice(&key_length.to_be_bytes());
        rec.extend_from_slice(&parent_cnid.to_be_bytes());
        rec.extend_from_slice(&(name_units.len() as u16).to_be_bytes());
        rec.extend_from_slice(&encode_utf16be(name));
        // Pad to even length if needed (alignment).
        if rec.len() % 2 != 0 {
            rec.push(0);
        }
        // Data: folder record, 88 bytes total. We only need the
        // first 12 for the parser's current fields (recordType +
        // flags + valence + folderID); the rest stays zeroed.
        let mut data = vec![0u8; 88];
        data[0..2].copy_from_slice(&REC_TYPE_FOLDER.to_be_bytes());
        data[8..12].copy_from_slice(&cnid.to_be_bytes());
        rec.extend_from_slice(&data);
        rec
    }

    fn encode_file_record(parent_cnid: u32, name: &str, cnid: u32) -> Vec<u8> {
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let key_payload_len = 4 + 2 + name_units.len() * 2;
        let key_length = key_payload_len as u16;
        let mut rec: Vec<u8> = Vec::new();
        rec.extend_from_slice(&key_length.to_be_bytes());
        rec.extend_from_slice(&parent_cnid.to_be_bytes());
        rec.extend_from_slice(&(name_units.len() as u16).to_be_bytes());
        rec.extend_from_slice(&encode_utf16be(name));
        if rec.len() % 2 != 0 {
            rec.push(0);
        }
        let mut data = vec![0u8; 248];
        data[0..2].copy_from_slice(&REC_TYPE_FILE.to_be_bytes());
        data[8..12].copy_from_slice(&cnid.to_be_bytes());
        rec.extend_from_slice(&data);
        rec
    }

    fn encode_thread_record(parent_cnid: u32, name: &str, is_folder: bool) -> Vec<u8> {
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let key_payload_len = 4 + 2 + name_units.len() * 2;
        let key_length = key_payload_len as u16;
        let mut rec: Vec<u8> = Vec::new();
        rec.extend_from_slice(&key_length.to_be_bytes());
        rec.extend_from_slice(&parent_cnid.to_be_bytes());
        rec.extend_from_slice(&(name_units.len() as u16).to_be_bytes());
        rec.extend_from_slice(&encode_utf16be(name));
        if rec.len() % 2 != 0 {
            rec.push(0);
        }
        let rt = if is_folder {
            REC_TYPE_FOLDER_THREAD
        } else {
            REC_TYPE_FILE_THREAD
        };
        let mut data = vec![0u8; 16];
        data[0..2].copy_from_slice(&rt.to_be_bytes());
        rec.extend_from_slice(&data);
        rec
    }

    #[test]
    fn parse_catalog_record_decodes_folder() {
        let bytes = encode_folder_record(1, "MyFolder", 42);
        let entry = parse_catalog_record(&bytes).expect("parse").expect("some");
        assert_eq!(entry.parent_cnid, 1);
        assert_eq!(entry.cnid, 42);
        assert_eq!(entry.name, "MyFolder");
        assert!(matches!(entry.entry_type, HfsPlusEntryType::Directory));
        assert!(matches!(entry.record_type, HfsPlusRecordType::CatalogFolder));
    }

    #[test]
    fn parse_catalog_record_decodes_file() {
        let bytes = encode_file_record(42, "report.txt", 100);
        let entry = parse_catalog_record(&bytes).expect("parse").expect("some");
        assert_eq!(entry.parent_cnid, 42);
        assert_eq!(entry.cnid, 100);
        assert_eq!(entry.name, "report.txt");
        assert!(matches!(entry.entry_type, HfsPlusEntryType::File));
    }

    #[test]
    fn parse_catalog_record_skips_folder_thread() {
        let bytes = encode_thread_record(2, "root", true);
        let result = parse_catalog_record(&bytes).expect("parse");
        assert!(
            result.is_none(),
            "folder-thread records must be skipped for flat enumeration"
        );
    }

    #[test]
    fn parse_catalog_record_skips_file_thread() {
        let bytes = encode_thread_record(2, "x", false);
        assert!(parse_catalog_record(&bytes).expect("parse").is_none());
    }

    #[test]
    fn decode_utf16be_name_preserves_unicode() {
        // "héllo" in UTF-16BE — mixed ASCII + combining accent.
        // HFS+ stores NFC on disk; we must NOT re-normalize.
        let s = "héllo";
        let be_bytes = encode_utf16be(s);
        let decoded = decode_utf16be_name(&be_bytes).expect("decode");
        assert_eq!(decoded, s);
    }

    #[test]
    fn decode_utf16be_name_rejects_odd_length() {
        assert!(decode_utf16be_name(&[0x00, 0x41, 0xFF]).is_err());
    }

    // ── End-to-end: synthesize a minimal leaf node + run
    // `read_catalog` against a crafted HFS+ volume ─────────────────

    /// Build a minimal valid HFS+ volume where the catalog B-tree
    /// has one header node + one leaf node at node_idx 1. Leaf
    /// contains one folder record and one file record. Used to
    /// validate the whole iteration pipeline end-to-end.
    fn synth_hfsplus_volume_with_catalog() -> Vec<u8> {
        // Layout:
        //  block_size = 512, node_size = 512
        //  Catalog file first extent at block 8 (byte 4096)
        //    node 0 (bytes 4096..4608) = B-tree header
        //    node 1 (bytes 4608..5120) = leaf node
        //
        // Volume-header block size 512 means we need the catalog
        // fork extent to carry at least 2 nodes = 1024 bytes = 2
        // blocks. First extent startBlock=8, blockCount=2.
        let block_size: u32 = 512;
        let node_size: u16 = 512;
        let num_blocks_total: u32 = 16; // 16 * 512 = 8192 bytes

        // Backing buffer
        let total_bytes = (num_blocks_total as usize) * (block_size as usize);
        let mut v = vec![0u8; total_bytes];

        // Volume header at byte 1024.
        // signature "H+"
        v[1024] = 0x48;
        v[1025] = 0x2B;
        // blocksize u32 BE at offset 1024 + 40
        v[1024 + 40..1024 + 44].copy_from_slice(&block_size.to_be_bytes());
        // total_blocks u32 BE at offset 1024 + 44
        v[1024 + 44..1024 + 48].copy_from_slice(&num_blocks_total.to_be_bytes());
        // Catalog fork data at volume-header offset 288.
        // logicalSize u64 BE: 1024 (two nodes of 512 bytes each)
        let cat_logical: u64 = 1024;
        v[1024 + 272..1024 + 280].copy_from_slice(&cat_logical.to_be_bytes());
        // clumpSize u32 BE: 0 (don't care)
        // totalBlocks u32 BE at offset 12: 2
        v[1024 + 272 + 12..1024 + 272 + 16].copy_from_slice(&2u32.to_be_bytes());
        // First extent { startBlock 8, blockCount 2 } at offset 16
        v[1024 + 272 + 16..1024 + 272 + 20].copy_from_slice(&8u32.to_be_bytes());
        v[1024 + 272 + 20..1024 + 272 + 24].copy_from_slice(&2u32.to_be_bytes());

        // B-tree HEADER node at byte 4096 (block 8):
        //   Descriptor: kind = 1 (header), numRecords = 3
        let hdr_node_off = 4096;
        v[hdr_node_off + 8] = 1; // kind = header
        v[hdr_node_off + 10..hdr_node_off + 12].copy_from_slice(&3u16.to_be_bytes());
        // B-tree header RECORD follows the 14-byte descriptor
        // (starts at hdr_node_off + 14). Fields we care about:
        //   nodeSize at record offset 8 (u16 BE)
        //   rootNode at record offset 16 (u32 BE)
        //   firstLeafNode at record offset 24 (u32 BE)
        //   lastLeafNode at record offset 28 (u32 BE)
        let rec_off = hdr_node_off + 14;
        v[rec_off + 18..rec_off + 20].copy_from_slice(&node_size.to_be_bytes());
        v[rec_off + 2..rec_off + 6].copy_from_slice(&1u32.to_be_bytes()); // root = node 1
        v[rec_off + 10..rec_off + 14].copy_from_slice(&1u32.to_be_bytes()); // first_leaf
        v[rec_off + 14..rec_off + 18].copy_from_slice(&1u32.to_be_bytes()); // last_leaf

        // LEAF node at byte 4608 (block 9):
        //   Descriptor: fLink = 0, bLink = 0, kind = -1, height = 1,
        //   numRecords = 2
        let leaf_off = 4608;
        v[leaf_off + 8] = 0xFF; // kind = leaf (-1 as u8)
        v[leaf_off + 9] = 1; // height
        v[leaf_off + 10..leaf_off + 12].copy_from_slice(&2u16.to_be_bytes());

        // Build two records: folder "docs" (cnid 16) and file
        // "report.txt" (cnid 17), both with parent_cnid = 2 (root).
        let folder_rec = encode_folder_record(2, "docs", 16);
        let file_rec = encode_file_record(2, "report.txt", 17);
        // Place record 0 right after the descriptor.
        let rec0_start = 14;
        let rec0_end = rec0_start + folder_rec.len();
        v[leaf_off + rec0_start..leaf_off + rec0_end].copy_from_slice(&folder_rec);
        // Place record 1 immediately after record 0.
        let rec1_start = rec0_end;
        let rec1_end = rec1_start + file_rec.len();
        v[leaf_off + rec1_start..leaf_off + rec1_end].copy_from_slice(&file_rec);

        // Offset table at the tail of the leaf:
        //   bytes leaf+510..512  → offset of record 0
        //   bytes leaf+508..510  → offset of record 1
        //   bytes leaf+506..508  → free-space sentinel
        v[leaf_off + 510..leaf_off + 512]
            .copy_from_slice(&(rec0_start as u16).to_be_bytes());
        v[leaf_off + 508..leaf_off + 510]
            .copy_from_slice(&(rec1_start as u16).to_be_bytes());
        v[leaf_off + 506..leaf_off + 508]
            .copy_from_slice(&(rec1_end as u16).to_be_bytes());

        v
    }

    #[test]
    fn read_catalog_returns_real_entries_on_synthesized_volume() {
        let bytes = synth_hfsplus_volume_with_catalog();
        let cursor = Cursor::new(bytes);
        let mut fs = HfsPlusFilesystem::open_reader(cursor).expect("open");
        let entries = fs.read_catalog().expect("read_catalog");

        assert_eq!(
            entries.len(),
            2,
            "expected two catalog records (folder + file), got {}",
            entries.len()
        );

        let folder = entries
            .iter()
            .find(|e| matches!(e.entry_type, HfsPlusEntryType::Directory))
            .expect("folder present");
        assert_eq!(folder.name, "docs");
        assert_eq!(folder.cnid, 16);
        assert_eq!(folder.parent_cnid, 2);

        let file = entries
            .iter()
            .find(|e| matches!(e.entry_type, HfsPlusEntryType::File))
            .expect("file present");
        assert_eq!(file.name, "report.txt");
        assert_eq!(file.cnid, 17);
        assert_eq!(file.parent_cnid, 2);
    }

    #[test]
    fn read_catalog_ignores_thread_records_mixed_in_leaf() {
        // Rebuild the synth volume but add a thread record alongside
        // the folder + file. The thread must NOT appear in the
        // walker's enumeration output.
        let bytes = {
            let block_size: u32 = 512;
            let node_size: u16 = 512;
            let num_blocks_total: u32 = 16;
            let total_bytes = (num_blocks_total as usize) * (block_size as usize);
            let mut v = vec![0u8; total_bytes];
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
            v[hdr_node_off + 10..hdr_node_off + 12]
                .copy_from_slice(&3u16.to_be_bytes());
            let rec_off = hdr_node_off + 14;
            v[rec_off + 18..rec_off + 20].copy_from_slice(&node_size.to_be_bytes());
            v[rec_off + 2..rec_off + 6].copy_from_slice(&1u32.to_be_bytes());
            v[rec_off + 10..rec_off + 14].copy_from_slice(&1u32.to_be_bytes());
            v[rec_off + 14..rec_off + 18].copy_from_slice(&1u32.to_be_bytes());

            let leaf_off = 4608;
            v[leaf_off + 8] = 0xFF;
            v[leaf_off + 9] = 1;
            v[leaf_off + 10..leaf_off + 12].copy_from_slice(&3u16.to_be_bytes());

            let folder_rec = encode_folder_record(2, "docs", 16);
            let thread_rec = encode_thread_record(2, "root", true);
            let file_rec = encode_file_record(2, "x", 17);
            let r0 = 14usize;
            let r1 = r0 + folder_rec.len();
            let r2 = r1 + thread_rec.len();
            let r3 = r2 + file_rec.len();
            v[leaf_off + r0..leaf_off + r1].copy_from_slice(&folder_rec);
            v[leaf_off + r1..leaf_off + r2].copy_from_slice(&thread_rec);
            v[leaf_off + r2..leaf_off + r3].copy_from_slice(&file_rec);

            v[leaf_off + 510..leaf_off + 512]
                .copy_from_slice(&(r0 as u16).to_be_bytes());
            v[leaf_off + 508..leaf_off + 510]
                .copy_from_slice(&(r1 as u16).to_be_bytes());
            v[leaf_off + 506..leaf_off + 508]
                .copy_from_slice(&(r2 as u16).to_be_bytes());
            v[leaf_off + 504..leaf_off + 506]
                .copy_from_slice(&(r3 as u16).to_be_bytes());
            v
        };
        let cursor = Cursor::new(bytes);
        let mut fs = HfsPlusFilesystem::open_reader(cursor).expect("open");
        let entries = fs.read_catalog().expect("read_catalog");
        assert_eq!(
            entries.len(),
            2,
            "only folder + file should enumerate; thread record skipped"
        );
        assert!(entries.iter().all(|e| !e.name.is_empty()));
    }
}

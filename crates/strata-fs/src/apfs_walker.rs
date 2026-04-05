//! Cross-platform APFS walker — reads from any Read + Seek source.
//!
//! Parses APFS container superblock, resolves volumes via OMAP B-tree,
//! then walks the filesystem B-tree to enumerate all files and directories.
//! Does NOT require macOS kernel APIs.
//!
//! Architecture:
//! 1. Read container superblock (NXSB) at block 0
//! 2. Resolve volume OIDs via container OMAP (virtual → physical)
//! 3. Parse each volume superblock (APSB) for root_tree_oid and omap_oid
//! 4. Resolve root_tree_oid via volume OMAP
//! 5. Walk filesystem B-tree recursively for J_DREC + J_INODE records
//! 6. Build path tree from parent references (same approach as MFT Walker)

use crate::errors::ForensicError;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use tracing::{info, warn};

// ─── Constants ───────────────────────────────────────────────────────────────

/// APFS Container superblock magic: "NXSB" (little-endian)
const NX_MAGIC: u32 = 0x4253_584E;

/// APFS Volume superblock magic: "APSB" (little-endian)
const APSB_MAGIC: u32 = 0x4253_5041;

/// APFS nanoseconds epoch offset: seconds from 2001-01-01 to 1970-01-01
const APFS_EPOCH_OFFSET: i64 = 978_307_200;

/// Root directory inode number in APFS
const ROOT_DIR_INODE: u64 = 2;

// B-tree node flags
const BTNODE_LEAF: u16 = 0x0002;
const BTNODE_FIXED_KV: u16 = 0x0004;

// APFS filesystem object types (top nibble of obj_id_and_type)
const APFS_TYPE_INODE: u64 = 3;
const APFS_TYPE_DIR_REC: u64 = 9;

/// Maximum recursion depth for B-tree traversal
const MAX_BTREE_DEPTH: u32 = 16;

// ─── Public Types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ApfsBootParams {
    pub block_size: u32,
    pub total_blocks: u64,
    pub num_volumes: u32,
    pub volume_offsets: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct ApfsFileEntry {
    pub inode: u64,
    pub name: String,
    pub parent_inode: u64,
    pub size: u64,
    pub is_directory: bool,
    pub is_symlink: bool,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    pub changed: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ApfsPathEntry {
    pub inode: u64,
    pub path: String,
    pub name: String,
    pub size: u64,
    pub is_directory: bool,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
}

/// Parsed volume superblock fields needed for B-tree traversal.
#[derive(Debug, Clone)]
struct VolumeSuperblock {
    omap_oid: u64,
    root_tree_oid: u64,
    vol_name: String,
    #[allow(dead_code)]
    role: u16,
}

/// OMAP mapping: virtual OID → physical block address.
struct OmapCache {
    entries: HashMap<u64, u64>,
}

// ─── ApfsWalker ──────────────────────────────────────────────────────────────

pub struct ApfsWalker<R: Read + Seek> {
    reader: R,
    boot: ApfsBootParams,
    partition_offset: u64,
}

impl<R: Read + Seek> ApfsWalker<R> {
    /// Create a new ApfsWalker by reading the APFS container superblock.
    pub fn new(mut reader: R, partition_offset: u64) -> Result<Self, ForensicError> {
        let boot = Self::read_container_superblock(&mut reader, partition_offset)?;
        info!(
            "[ApfsWalker] Container: block_size={} total_blocks={} volumes={}",
            boot.block_size, boot.total_blocks, boot.num_volumes
        );
        Ok(Self {
            reader,
            boot,
            partition_offset,
        })
    }

    fn read_container_superblock(
        reader: &mut R,
        offset: u64,
    ) -> Result<ApfsBootParams, ForensicError> {
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(ForensicError::Io)?;
        let mut header = [0u8; 4096];
        reader
            .read_exact(&mut header)
            .map_err(ForensicError::Io)?;

        // Magic at offset 32 (after 32-byte obj_phys_t header)
        let magic = u32::from_le_bytes(header[32..36].try_into().unwrap_or([0; 4]));
        if magic != NX_MAGIC {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        let block_size = u32::from_le_bytes(header[36..40].try_into().unwrap_or([0; 4]));
        let total_blocks = u64::from_le_bytes(header[40..48].try_into().unwrap_or([0; 8]));

        if block_size == 0 || block_size > 65536 {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        // Volume OIDs at offset 184 (nx_fs_oid array, up to 100 entries)
        let mut volume_oids = Vec::new();
        for i in 0..100 {
            let field_offset = 184 + (i * 8);
            if field_offset + 8 > header.len() {
                break;
            }
            let oid =
                u64::from_le_bytes(header[field_offset..field_offset + 8].try_into().unwrap_or([0; 8]));
            if oid != 0 {
                volume_oids.push(oid);
            }
        }

        let num_volumes = volume_oids.len() as u32;

        Ok(ApfsBootParams {
            block_size,
            total_blocks,
            num_volumes,
            volume_offsets: volume_oids,
        })
    }

    /// Read a single block at the given block number.
    fn read_block(&mut self, block_num: u64) -> Result<Vec<u8>, ForensicError> {
        if block_num >= self.boot.total_blocks {
            return Err(ForensicError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("block {} beyond total {}", block_num, self.boot.total_blocks),
            )));
        }
        let offset = self.partition_offset + block_num * self.boot.block_size as u64;
        self.reader
            .seek(SeekFrom::Start(offset))
            .map_err(ForensicError::Io)?;
        let mut buf = vec![0u8; self.boot.block_size as usize];
        self.reader
            .read_exact(&mut buf)
            .map_err(ForensicError::Io)?;
        Ok(buf)
    }

    // ── Container OMAP resolution ───────────────────────────────────────────

    /// Read the container OMAP and build an OID→paddr cache.
    fn read_container_omap(&mut self) -> Result<OmapCache, ForensicError> {
        // Re-read superblock to get omap_oid at offset 160
        self.reader
            .seek(SeekFrom::Start(self.partition_offset))
            .map_err(ForensicError::Io)?;
        let mut header = [0u8; 4096];
        self.reader
            .read_exact(&mut header)
            .map_err(ForensicError::Io)?;

        let omap_oid = u64::from_le_bytes(header[160..168].try_into().unwrap_or([0; 8]));
        self.read_omap_tree(omap_oid)
    }

    /// Read an OMAP B-tree starting from the given OMAP object block.
    fn read_omap_tree(&mut self, omap_block: u64) -> Result<OmapCache, ForensicError> {
        let mut cache = OmapCache {
            entries: HashMap::new(),
        };

        if omap_block == 0 || omap_block >= self.boot.total_blocks {
            return Ok(cache);
        }

        let omap_data = self.read_block(omap_block)?;
        if omap_data.len() < 56 {
            return Ok(cache);
        }

        // OMAP phys: obj_phys_t (32 bytes) + om_flags(4) + om_snap_count(4) +
        // om_tree_type(4) + om_snapshot_tree_type(4) + om_tree_oid(8)
        let om_tree_oid = u64::from_le_bytes(
            omap_data[48..56].try_into().unwrap_or([0; 8]),
        );

        if om_tree_oid > 0 && om_tree_oid < self.boot.total_blocks {
            self.walk_omap_btree(om_tree_oid, &mut cache, 0);
        }

        info!("[ApfsWalker] OMAP cache: {} entries", cache.entries.len());
        Ok(cache)
    }

    /// Recursively walk an OMAP B-tree to collect all OID→paddr mappings.
    fn walk_omap_btree(
        &mut self,
        block_num: u64,
        cache: &mut OmapCache,
        depth: u32,
    ) {
        if depth > MAX_BTREE_DEPTH || block_num >= self.boot.total_blocks {
            return;
        }

        let Ok(node) = self.read_block(block_num) else {
            return;
        };
        if node.len() < 56 {
            return;
        }

        // B-tree node header starts at offset 32 (after obj_phys_t)
        let btn_flags = u16::from_le_bytes(node[32..34].try_into().unwrap_or([0; 2]));
        let btn_level = u16::from_le_bytes(node[34..36].try_into().unwrap_or([0; 2]));
        let btn_nkeys = u32::from_le_bytes(node[36..40].try_into().unwrap_or([0; 4])) as usize;
        let tspace_off = u16::from_le_bytes(node[40..42].try_into().unwrap_or([0; 2])) as usize;

        if btn_nkeys == 0 || btn_nkeys > 10000 {
            return;
        }

        let is_fixed = (btn_flags & BTNODE_FIXED_KV) != 0;
        let toc_start = 56 + tspace_off;
        let toc_entry_size = if is_fixed { 4 } else { 8 };
        let key_area_start = toc_start + (btn_nkeys * toc_entry_size);

        if btn_level > 0 {
            // Non-leaf: recurse into children
            for i in 0..btn_nkeys {
                let entry_off = toc_start + (i * toc_entry_size);
                if entry_off + toc_entry_size > node.len() {
                    break;
                }

                let vn_off = u16::from_le_bytes(
                    node[entry_off + 2..entry_off + 4].try_into().unwrap_or([0; 2]),
                ) as usize;

                // For non-leaf OMAP nodes, value is at end-of-block minus offset
                let val_abs = node.len().saturating_sub(vn_off);
                if val_abs + 8 <= node.len() {
                    let child = u64::from_le_bytes(
                        node[val_abs..val_abs + 8].try_into().unwrap_or([0; 8]),
                    );
                    if child > 0 && child < self.boot.total_blocks {
                        self.walk_omap_btree(child, cache, depth + 1);
                    }
                }
            }
        } else {
            // Leaf: extract OID→paddr mappings
            for i in 0..btn_nkeys {
                let entry_off = toc_start + (i * toc_entry_size);
                if entry_off + toc_entry_size > node.len() {
                    break;
                }

                let kn_off = u16::from_le_bytes(
                    node[entry_off..entry_off + 2].try_into().unwrap_or([0; 2]),
                ) as usize;
                let vn_off = u16::from_le_bytes(
                    node[entry_off + 2..entry_off + 4].try_into().unwrap_or([0; 2]),
                ) as usize;

                let key_abs = key_area_start + kn_off;
                let val_abs = node.len().saturating_sub(vn_off);

                // OMAP key: u64 oid + u64 xid = 16 bytes
                // OMAP val: u32 flags + u32 size + u64 paddr = 16 bytes
                if key_abs + 8 <= node.len() && val_abs + 16 <= node.len() {
                    let oid = u64::from_le_bytes(
                        node[key_abs..key_abs + 8].try_into().unwrap_or([0; 8]),
                    );
                    let paddr = u64::from_le_bytes(
                        node[val_abs + 8..val_abs + 16].try_into().unwrap_or([0; 8]),
                    );
                    if oid > 0 && paddr > 0 && paddr < self.boot.total_blocks {
                        cache.entries.insert(oid, paddr);
                    }
                }
            }
        }
    }

    // ── Volume superblock parsing ───────────────────────────────────────────

    /// Parse an APSB volume superblock at the given physical block.
    fn parse_volume_superblock(&mut self, block_num: u64) -> Option<VolumeSuperblock> {
        let block = self.read_block(block_num).ok()?;
        if block.len() < 200 {
            return None;
        }

        let magic = u32::from_le_bytes(block[32..36].try_into().unwrap_or([0; 4]));
        if magic != APSB_MAGIC {
            return None;
        }

        // apfs_superblock_t after obj_phys_t (32 bytes):
        // Offset 32:  magic
        // Offset 36:  fs_index (u32)
        // Offset 40:  features (u64)
        // Offset 48:  readonly_compat (u64)
        // Offset 56:  incompat_features (u64)
        // Offset 64:  unmount_time (u64)
        // Offset 72:  fs_reserve_block_count (u64)
        // Offset 80:  fs_quota_block_count (u64)
        // Offset 88:  fs_alloc_count (u64)
        // Offset 96:  ... (wrapped_meta_crypto_state, 20 bytes)
        // Offset 116: root_tree_type (u32)
        // Offset 120: extentref_tree_type (u32)
        // Offset 124: snap_meta_tree_type (u32)
        // Offset 128: omap_oid (u64)
        // Offset 136: root_tree_oid (u64)
        // Offset 144: extentref_tree_oid (u64)
        // Offset 152: snap_meta_tree_oid (u64)
        // ...
        // Offset 704: vol_name (256 bytes UTF-8)
        // Offset 964: role (u16)

        let omap_oid = u64::from_le_bytes(block[128..136].try_into().unwrap_or([0; 8]));
        let root_tree_oid = u64::from_le_bytes(block[136..144].try_into().unwrap_or([0; 8]));

        let vol_name = if block.len() >= 960 {
            let name_bytes = &block[704..960];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
            String::from_utf8_lossy(&name_bytes[..end]).to_string()
        } else {
            String::new()
        };

        let role = if block.len() >= 966 {
            u16::from_le_bytes(block[964..966].try_into().unwrap_or([0; 2]))
        } else {
            0
        };

        info!(
            "[ApfsWalker] Volume '{}' role={} omap_oid={} root_tree_oid={}",
            vol_name, role, omap_oid, root_tree_oid
        );

        Some(VolumeSuperblock {
            omap_oid,
            root_tree_oid,
            vol_name,
            role,
        })
    }

    // ── Main enumeration ────────────────────────────────────────────────────

    /// Enumerate all files across all volumes using proper B-tree traversal.
    pub fn enumerate(&mut self, max_entries: u32) -> Result<Vec<ApfsFileEntry>, ForensicError> {
        let mut all_entries = Vec::new();
        let mut inode_metadata: HashMap<u64, InodeMeta> = HashMap::new();

        // Step 1: Build container OMAP to resolve volume OIDs
        let container_omap = self.read_container_omap()?;

        // Step 2: Resolve volume OIDs to physical block addresses
        let vol_oids = self.boot.volume_offsets.clone();
        let mut vol_blocks = Vec::new();

        for &oid in &vol_oids {
            // Try container OMAP first (virtual OIDs)
            if let Some(&paddr) = container_omap.entries.get(&oid) {
                if let Some(vsb) = self.parse_volume_superblock(paddr) {
                    vol_blocks.push((paddr, vsb));
                    continue;
                }
            }
            // Fall back: treat OID as physical block number
            if oid < self.boot.total_blocks {
                if let Some(vsb) = self.parse_volume_superblock(oid) {
                    vol_blocks.push((oid, vsb));
                }
            }
        }

        // Strategy fallback: scan first 10k blocks for APSB if OMAP failed
        if vol_blocks.is_empty() {
            warn!("[ApfsWalker] OMAP resolution failed, scanning for APSB blocks");
            let scan_limit = self.boot.total_blocks.min(10_000);
            for b in 0..scan_limit {
                if let Some(vsb) = self.parse_volume_superblock(b) {
                    vol_blocks.push((b, vsb));
                }
            }
        }

        if vol_blocks.is_empty() {
            warn!("[ApfsWalker] No volume superblocks found");
            return Ok(all_entries);
        }

        // Step 3: For each volume, walk its filesystem B-tree
        for (_vol_block, vsb) in &vol_blocks {
            if all_entries.len() >= max_entries as usize {
                break;
            }

            info!(
                "[ApfsWalker] Walking volume '{}' root_tree_oid={}",
                vsb.vol_name, vsb.root_tree_oid
            );

            // Build volume OMAP for resolving filesystem virtual OIDs
            let vol_omap = self.read_omap_tree(vsb.omap_oid)?;

            // Resolve root_tree_oid via volume OMAP
            let root_paddr = vol_omap
                .entries
                .get(&vsb.root_tree_oid)
                .copied()
                .unwrap_or(vsb.root_tree_oid);

            if root_paddr == 0 || root_paddr >= self.boot.total_blocks {
                warn!(
                    "[ApfsWalker] root_tree paddr {} invalid for volume '{}'",
                    root_paddr, vsb.vol_name
                );
                // Fall back to heuristic scan for this volume
                self.heuristic_scan(
                    &vol_blocks.iter().map(|(b, _)| *b).collect::<Vec<_>>(),
                    max_entries,
                    &mut all_entries,
                    &mut inode_metadata,
                )?;
                continue;
            }

            // The root of the FS B-tree might be a btree_info_t wrapper
            // Read the root block to check
            let root_block = self.read_block(root_paddr)?;
            if root_block.len() < 56 {
                continue;
            }

            // Walk the filesystem B-tree
            let remaining = max_entries as usize - all_entries.len();
            self.walk_fs_btree(
                root_paddr,
                &vol_omap,
                &mut all_entries,
                &mut inode_metadata,
                remaining,
                0,
            );

            info!(
                "[ApfsWalker] Volume '{}': {} dir entries, {} inode records",
                vsb.vol_name,
                all_entries.len(),
                inode_metadata.len()
            );
        }

        // If B-tree walk found nothing, fall back to heuristic block scan
        if all_entries.is_empty() {
            warn!("[ApfsWalker] B-tree walk returned no entries, falling back to heuristic scan");
            let vol_block_nums: Vec<u64> = vol_blocks.iter().map(|(b, _)| *b).collect();
            self.heuristic_scan(
                &vol_block_nums,
                max_entries,
                &mut all_entries,
                &mut inode_metadata,
            )?;
        }

        // Merge inode metadata into directory entries
        for entry in &mut all_entries {
            if let Some(meta) = inode_metadata.get(&entry.inode) {
                if entry.size == 0 {
                    entry.size = meta.size;
                }
                if entry.created.is_none() {
                    entry.created = meta.created;
                }
                if entry.modified.is_none() {
                    entry.modified = meta.modified;
                }
                if entry.accessed.is_none() {
                    entry.accessed = meta.accessed;
                }
                if entry.changed.is_none() {
                    entry.changed = meta.changed;
                }
            }
        }

        // Deduplicate by (parent_inode, name)
        all_entries.sort_by(|a, b| {
            a.parent_inode
                .cmp(&b.parent_inode)
                .then(a.name.cmp(&b.name))
        });
        all_entries.dedup_by(|a, b| a.parent_inode == b.parent_inode && a.name == b.name);

        info!(
            "[ApfsWalker] Total: {} entries from {} volume(s)",
            all_entries.len(),
            vol_blocks.len()
        );

        Ok(all_entries)
    }

    /// Walk a filesystem B-tree node recursively, extracting J_DREC and J_INODE records.
    fn walk_fs_btree(
        &mut self,
        block_num: u64,
        vol_omap: &OmapCache,
        entries: &mut Vec<ApfsFileEntry>,
        inode_meta: &mut HashMap<u64, InodeMeta>,
        max_remaining: usize,
        depth: u32,
    ) {
        if depth > MAX_BTREE_DEPTH
            || block_num >= self.boot.total_blocks
            || entries.len() >= max_remaining
        {
            return;
        }

        let Ok(node) = self.read_block(block_num) else {
            return;
        };
        if node.len() < 56 {
            return;
        }

        // B-tree node header at offset 32 (after obj_phys_t)
        let btn_flags = u16::from_le_bytes(node[32..34].try_into().unwrap_or([0; 2]));
        let btn_level = u16::from_le_bytes(node[34..36].try_into().unwrap_or([0; 2]));
        let btn_nkeys = u32::from_le_bytes(node[36..40].try_into().unwrap_or([0; 4])) as usize;
        let tspace_off = u16::from_le_bytes(node[40..42].try_into().unwrap_or([0; 2])) as usize;

        if btn_nkeys == 0 || btn_nkeys > 10000 {
            return;
        }

        let is_leaf = btn_level == 0 || (btn_flags & BTNODE_LEAF) != 0;
        let is_fixed = (btn_flags & BTNODE_FIXED_KV) != 0;

        let toc_start = 56 + tspace_off;

        if is_leaf {
            // Leaf node: extract J_DREC and J_INODE records
            // Variable-length KV entries: each TOC entry is 8 bytes (koff, klen, voff, vlen)
            let toc_entry_size: usize = if is_fixed { 4 } else { 8 };
            let key_area_start = toc_start + (btn_nkeys * toc_entry_size);

            for i in 0..btn_nkeys {
                if entries.len() >= max_remaining {
                    break;
                }

                let entry_off = toc_start + (i * toc_entry_size);
                if entry_off + toc_entry_size > node.len() {
                    break;
                }

                let kn_off = u16::from_le_bytes(
                    node[entry_off..entry_off + 2].try_into().unwrap_or([0; 2]),
                ) as usize;

                let (kn_len, vn_off, vn_len) = if is_fixed {
                    let voff = u16::from_le_bytes(
                        node[entry_off + 2..entry_off + 4].try_into().unwrap_or([0; 2]),
                    ) as usize;
                    (0usize, voff, 0usize)
                } else {
                    let kl = u16::from_le_bytes(
                        node[entry_off + 2..entry_off + 4].try_into().unwrap_or([0; 2]),
                    ) as usize;
                    let vo = u16::from_le_bytes(
                        node[entry_off + 4..entry_off + 6].try_into().unwrap_or([0; 2]),
                    ) as usize;
                    let vl = u16::from_le_bytes(
                        node[entry_off + 6..entry_off + 8].try_into().unwrap_or([0; 2]),
                    ) as usize;
                    (kl, vo, vl)
                };

                let key_abs = key_area_start + kn_off;
                let val_abs = node.len().saturating_sub(vn_off);

                if key_abs + 8 > node.len() {
                    continue;
                }

                // First 8 bytes of every FS key: obj_id_and_type
                let obj_id_and_type = u64::from_le_bytes(
                    node[key_abs..key_abs + 8].try_into().unwrap_or([0; 8]),
                );
                let kind = obj_id_and_type >> 60;
                let obj_id = obj_id_and_type & 0x0FFF_FFFF_FFFF_FFFF;

                match kind {
                    APFS_TYPE_DIR_REC => {
                        // J_DREC key: obj_id_and_type(8) + name_len_and_hash(4) + name(variable)
                        if key_abs + 12 > node.len() {
                            continue;
                        }
                        let name_len_hash = u32::from_le_bytes(
                            node[key_abs + 8..key_abs + 12].try_into().unwrap_or([0; 4]),
                        );
                        let name_len = (name_len_hash & 0x03FF) as usize;

                        if name_len == 0
                            || name_len > 255
                            || key_abs + 12 + name_len > node.len()
                        {
                            continue;
                        }

                        let name_raw = &node[key_abs + 12..key_abs + 12 + name_len];
                        let name = String::from_utf8_lossy(name_raw)
                            .trim_matches('\0')
                            .to_string();

                        if name.is_empty() {
                            continue;
                        }

                        // J_DREC value: u64 file_id, u64 date_added, u16 flags
                        if val_abs + 18 > node.len() {
                            continue;
                        }
                        let file_id = u64::from_le_bytes(
                            node[val_abs..val_abs + 8].try_into().unwrap_or([0; 8]),
                        );
                        let date_added_ns = i64::from_le_bytes(
                            node[val_abs + 8..val_abs + 16].try_into().unwrap_or([0; 8]),
                        );
                        let d_flags = u16::from_le_bytes(
                            node[val_abs + 16..val_abs + 18].try_into().unwrap_or([0; 2]),
                        );

                        // d_type is in the flags field: DT_DIR=4, DT_REG=8, DT_LNK=10
                        let is_directory = d_flags == 4;
                        let is_symlink = d_flags == 10;

                        if file_id == 0 {
                            continue;
                        }

                        entries.push(ApfsFileEntry {
                            inode: file_id,
                            name,
                            parent_inode: obj_id, // parent directory inode
                            size: 0,
                            is_directory,
                            is_symlink,
                            created: apfs_ns_to_unix(date_added_ns),
                            modified: None,
                            accessed: None,
                            changed: None,
                        });
                    }
                    APFS_TYPE_INODE => {
                        // J_INODE value: parent_id(8), private_id(8), create(8), mod(8),
                        //   change(8), access(8), internal_flags(8), nchildren(4), ...
                        let _ = kn_len;
                        let _ = vn_len;
                        if val_abs + 82 > node.len() {
                            // Need at least through mode field
                            continue;
                        }

                        let _parent_id = u64::from_le_bytes(
                            node[val_abs..val_abs + 8].try_into().unwrap_or([0; 8]),
                        );
                        let _private_id = u64::from_le_bytes(
                            node[val_abs + 8..val_abs + 16].try_into().unwrap_or([0; 8]),
                        );
                        let created_ns = i64::from_le_bytes(
                            node[val_abs + 16..val_abs + 24].try_into().unwrap_or([0; 8]),
                        );
                        let modified_ns = i64::from_le_bytes(
                            node[val_abs + 24..val_abs + 32].try_into().unwrap_or([0; 8]),
                        );
                        let changed_ns = i64::from_le_bytes(
                            node[val_abs + 32..val_abs + 40].try_into().unwrap_or([0; 8]),
                        );
                        let accessed_ns = i64::from_le_bytes(
                            node[val_abs + 40..val_abs + 48].try_into().unwrap_or([0; 8]),
                        );

                        // Size: after internal_flags(8) + nchildren(4) + default_protection(4)
                        //   + write_gen(4) + bsd_flags(4) + uid(4) + gid(4) + mode(2)
                        // That's 48 + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 2 = 82
                        // Actually the inode val layout is different. Let's try size from
                        // common offsets.
                        let size = if val_abs + 64 <= node.len() {
                            // Try at offset 56 (after internal_flags at 48)
                            // internal_flags(8) then nchildren_or_nlink(4) then...
                            // This is approximate; varies by APFS version
                            u64::from_le_bytes(
                                node[val_abs + 56..val_abs + 64]
                                    .try_into()
                                    .unwrap_or([0; 8]),
                            )
                        } else {
                            0
                        };

                        // Clamp unreasonable sizes (likely misparse)
                        let size = if size > 1_000_000_000_000 { 0 } else { size };

                        inode_meta.insert(
                            obj_id,
                            InodeMeta {
                                size,
                                created: apfs_ns_to_unix(created_ns),
                                modified: apfs_ns_to_unix(modified_ns),
                                accessed: apfs_ns_to_unix(accessed_ns),
                                changed: apfs_ns_to_unix(changed_ns),
                            },
                        );
                    }
                    _ => {} // Skip other record types
                }
            }
        } else {
            // Non-leaf node: recurse into children
            // For FS B-trees with variable KV, children are virtual OIDs that need OMAP lookup
            let toc_entry_size: usize = if is_fixed { 4 } else { 8 };
            for i in 0..btn_nkeys {
                if entries.len() >= max_remaining {
                    break;
                }

                let entry_off = toc_start + (i * toc_entry_size);
                if entry_off + toc_entry_size > node.len() {
                    break;
                }

                let vn_off = if is_fixed {
                    u16::from_le_bytes(
                        node[entry_off + 2..entry_off + 4].try_into().unwrap_or([0; 2]),
                    ) as usize
                } else {
                    u16::from_le_bytes(
                        node[entry_off + 4..entry_off + 6].try_into().unwrap_or([0; 2]),
                    ) as usize
                };

                let val_abs = node.len().saturating_sub(vn_off);
                if val_abs + 8 > node.len() {
                    continue;
                }

                // Non-leaf value is a child OID (virtual for FS trees)
                let child_oid = u64::from_le_bytes(
                    node[val_abs..val_abs + 8].try_into().unwrap_or([0; 8]),
                );

                if child_oid == 0 {
                    continue;
                }

                // Resolve virtual OID to physical address via volume OMAP
                let child_paddr = vol_omap
                    .entries
                    .get(&child_oid)
                    .copied()
                    .unwrap_or(child_oid);

                if child_paddr > 0 && child_paddr < self.boot.total_blocks {
                    self.walk_fs_btree(
                        child_paddr,
                        vol_omap,
                        entries,
                        inode_meta,
                        max_remaining,
                        depth + 1,
                    );
                }
            }
        }
    }

    /// Fallback: heuristic sequential block scan for leaf nodes.
    fn heuristic_scan(
        &mut self,
        vol_blocks: &[u64],
        max_entries: u32,
        entries: &mut Vec<ApfsFileEntry>,
        inode_meta: &mut HashMap<u64, InodeMeta>,
    ) -> Result<(), ForensicError> {
        let total = self.boot.total_blocks;
        let max_scan = total.min(100_000);

        for &vol_block in vol_blocks {
            let scan_end = (vol_block + 20_000).min(max_scan);
            for b in vol_block..scan_end {
                if entries.len() >= max_entries as usize {
                    return Ok(());
                }

                let Ok(node) = self.read_block(b) else {
                    continue;
                };
                if node.len() < 56 {
                    continue;
                }

                let flags = u16::from_le_bytes(node[32..34].try_into().unwrap_or([0; 2]));
                let level = u16::from_le_bytes(node[34..36].try_into().unwrap_or([0; 2]));

                if level == 0 && (flags & BTNODE_LEAF) != 0 {
                    let key_count =
                        u32::from_le_bytes(node[36..40].try_into().unwrap_or([0; 4])) as usize;
                    if key_count > 0 && key_count < 1000 {
                        extract_leaf_drec_entries(&node, key_count, entries);
                        extract_leaf_inode_entries(&node, key_count, inode_meta);
                    }
                }
            }
        }

        Ok(())
    }

    /// Enumerate and build full paths (same interface as MFT Walker).
    pub fn enumerate_with_paths(
        &mut self,
        max_entries: u32,
    ) -> Result<Vec<ApfsPathEntry>, ForensicError> {
        let entries = self.enumerate(max_entries)?;
        let paths = build_apfs_path_tree(&entries);
        info!(
            "[ApfsWalker] Built path tree: {} entries with paths",
            paths.len()
        );
        Ok(paths)
    }

    pub fn boot_params(&self) -> &ApfsBootParams {
        &self.boot
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

struct InodeMeta {
    size: u64,
    created: Option<i64>,
    modified: Option<i64>,
    accessed: Option<i64>,
    changed: Option<i64>,
}

/// Extract J_DREC entries from a leaf node (heuristic scanner fallback).
fn extract_leaf_drec_entries(
    node: &[u8],
    key_count: usize,
    entries: &mut Vec<ApfsFileEntry>,
) {
    let toc_offset = 56;

    for i in 0..key_count {
        let entry_off = toc_offset + (i * 8);
        if entry_off + 8 > node.len() {
            break;
        }

        let kn_off =
            u16::from_le_bytes(node[entry_off..entry_off + 2].try_into().unwrap_or([0; 2]))
                as usize;
        let vn_off =
            u16::from_le_bytes(node[entry_off + 2..entry_off + 4].try_into().unwrap_or([0; 2]))
                as usize;

        let key_area_start = toc_offset + (key_count * 8);
        let key_abs = key_area_start + kn_off;
        let val_abs = node.len().saturating_sub(vn_off);

        if key_abs + 12 >= node.len() || val_abs + 18 >= node.len() {
            continue;
        }

        let parent_id_and_type =
            u64::from_le_bytes(node[key_abs..key_abs + 8].try_into().unwrap_or([0; 8]));
        let kind = parent_id_and_type >> 60;
        let parent_inode = parent_id_and_type & 0x0FFF_FFFF_FFFF_FFFF;

        if kind != APFS_TYPE_DIR_REC {
            continue;
        }

        let name_len_hash =
            u32::from_le_bytes(node[key_abs + 8..key_abs + 12].try_into().unwrap_or([0; 4]));
        let name_len = (name_len_hash & 0x03FF) as usize;

        if name_len == 0 || name_len > 255 || key_abs + 12 + name_len > node.len() {
            continue;
        }

        let name = String::from_utf8_lossy(&node[key_abs + 12..key_abs + 12 + name_len])
            .trim_matches('\0')
            .to_string();
        if name.is_empty() {
            continue;
        }

        let file_id =
            u64::from_le_bytes(node[val_abs..val_abs + 8].try_into().unwrap_or([0; 8]));
        let date_ns =
            i64::from_le_bytes(node[val_abs + 8..val_abs + 16].try_into().unwrap_or([0; 8]));
        let d_flags =
            u16::from_le_bytes(node[val_abs + 16..val_abs + 18].try_into().unwrap_or([0; 2]));

        if file_id == 0 {
            continue;
        }

        entries.push(ApfsFileEntry {
            inode: file_id,
            name,
            parent_inode,
            size: 0,
            is_directory: d_flags == 4,
            is_symlink: d_flags == 10,
            created: apfs_ns_to_unix(date_ns),
            modified: None,
            accessed: None,
            changed: None,
        });
    }
}

/// Extract J_INODE records from a leaf node (heuristic scanner fallback).
fn extract_leaf_inode_entries(
    node: &[u8],
    key_count: usize,
    metadata: &mut HashMap<u64, InodeMeta>,
) {
    let toc_offset = 56;

    for i in 0..key_count {
        let entry_off = toc_offset + (i * 8);
        if entry_off + 8 > node.len() {
            break;
        }

        let kn_off =
            u16::from_le_bytes(node[entry_off..entry_off + 2].try_into().unwrap_or([0; 2]))
                as usize;
        let vn_off =
            u16::from_le_bytes(node[entry_off + 2..entry_off + 4].try_into().unwrap_or([0; 2]))
                as usize;

        let key_area_start = toc_offset + (key_count * 8);
        let key_abs = key_area_start + kn_off;
        let val_abs = node.len().saturating_sub(vn_off);

        if key_abs + 8 >= node.len() || val_abs + 48 >= node.len() {
            continue;
        }

        let inode_and_type =
            u64::from_le_bytes(node[key_abs..key_abs + 8].try_into().unwrap_or([0; 8]));
        let kind = inode_and_type >> 60;
        if kind != APFS_TYPE_INODE {
            continue;
        }
        let inode = inode_and_type & 0x0FFF_FFFF_FFFF_FFFF;
        if inode == 0 {
            continue;
        }

        let created_ns =
            i64::from_le_bytes(node[val_abs + 16..val_abs + 24].try_into().unwrap_or([0; 8]));
        let modified_ns =
            i64::from_le_bytes(node[val_abs + 24..val_abs + 32].try_into().unwrap_or([0; 8]));
        let changed_ns =
            i64::from_le_bytes(node[val_abs + 32..val_abs + 40].try_into().unwrap_or([0; 8]));
        let accessed_ns =
            i64::from_le_bytes(node[val_abs + 40..val_abs + 48].try_into().unwrap_or([0; 8]));

        let size = if val_abs + 64 <= node.len() {
            u64::from_le_bytes(node[val_abs + 56..val_abs + 64].try_into().unwrap_or([0; 8]))
        } else {
            0
        };
        let size = if size > 1_000_000_000_000 { 0 } else { size };

        metadata.insert(
            inode,
            InodeMeta {
                size,
                created: apfs_ns_to_unix(created_ns),
                modified: apfs_ns_to_unix(modified_ns),
                accessed: apfs_ns_to_unix(accessed_ns),
                changed: apfs_ns_to_unix(changed_ns),
            },
        );
    }
}

/// Convert APFS nanosecond timestamp to Unix seconds.
fn apfs_ns_to_unix(ns: i64) -> Option<i64> {
    if ns == 0 {
        return None;
    }
    let secs = ns / 1_000_000_000;
    let unix = secs + APFS_EPOCH_OFFSET;
    if !(0..=4_102_444_800).contains(&unix) {
        return None;
    }
    Some(unix)
}

/// Build full paths from parent references.
fn build_apfs_path_tree(entries: &[ApfsFileEntry]) -> Vec<ApfsPathEntry> {
    let mut by_inode: HashMap<u64, &ApfsFileEntry> = HashMap::with_capacity(entries.len());
    for entry in entries {
        by_inode.insert(entry.inode, entry);
    }

    let mut path_cache: HashMap<u64, String> = HashMap::new();
    path_cache.insert(ROOT_DIR_INODE, String::new());

    let mut result = Vec::with_capacity(entries.len());

    for entry in entries {
        if entry.inode == ROOT_DIR_INODE && entry.name.is_empty() {
            continue;
        }

        let full_path = resolve_apfs_path(entry.inode, &by_inode, &mut path_cache);
        let full_path = if full_path.is_empty() {
            format!("/{}", entry.name)
        } else {
            full_path
        };

        result.push(ApfsPathEntry {
            inode: entry.inode,
            path: full_path,
            name: entry.name.clone(),
            size: entry.size,
            is_directory: entry.is_directory,
            created: entry.created,
            modified: entry.modified,
            accessed: entry.accessed,
        });
    }

    result
}

/// Resolve the full path for a given inode (including the inode's own name).
fn resolve_apfs_path(
    inode: u64,
    by_inode: &HashMap<u64, &ApfsFileEntry>,
    cache: &mut HashMap<u64, String>,
) -> String {
    if let Some(cached) = cache.get(&inode) {
        return cached.clone();
    }

    let mut chain: Vec<(u64, String)> = Vec::new();
    let mut current = inode;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == ROOT_DIR_INODE || current == 0 || visited.contains(&current) {
            break;
        }
        visited.insert(current);
        if let Some(entry) = by_inode.get(&current) {
            chain.push((current, entry.name.clone()));
            current = entry.parent_inode;
        } else {
            break;
        }
    }

    chain.reverse();

    let mut accumulated = String::new();
    for (ino, name) in &chain {
        if !name.is_empty() {
            accumulated = format!("{}/{}", accumulated, name);
        }
        cache.insert(*ino, accumulated.clone());
    }

    accumulated
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apfs_ns_to_unix() {
        // 2024-01-01 00:00:00 UTC
        // Seconds since 2001-01-01 = 725846400
        let ns = 725_846_400_000_000_000i64;
        let unix = apfs_ns_to_unix(ns);
        assert!(unix.is_some());
        let ts = unix.unwrap();
        assert!(
            (ts - 1_704_153_600).abs() < 86400,
            "Expected ~1704153600, got {}",
            ts
        );
    }

    #[test]
    fn test_apfs_ns_zero_returns_none() {
        assert_eq!(apfs_ns_to_unix(0), None);
    }

    #[test]
    fn test_apfs_container_magic() {
        let mut block = [0u8; 4096];
        block[32..36].copy_from_slice(&NX_MAGIC.to_le_bytes());
        block[36..40].copy_from_slice(&4096u32.to_le_bytes());
        block[40..48].copy_from_slice(&1000u64.to_le_bytes());

        let mut cursor = std::io::Cursor::new(&block[..]);
        let result = ApfsWalker::read_container_superblock(&mut cursor, 0);
        assert!(result.is_ok());
        let boot = result.unwrap();
        assert_eq!(boot.block_size, 4096);
        assert_eq!(boot.total_blocks, 1000);
    }

    #[test]
    fn test_apfs_volume_superblock_offsets() {
        // Verify volume superblock magic position
        let mut block = vec![0u8; 4096];
        // APSB magic at offset 32
        block[32..36].copy_from_slice(&APSB_MAGIC.to_le_bytes());
        // omap_oid at offset 128
        block[128..136].copy_from_slice(&42u64.to_le_bytes());
        // root_tree_oid at offset 136
        block[136..144].copy_from_slice(&99u64.to_le_bytes());
        // Volume name at offset 704
        let name = b"TestVolume";
        block[704..704 + name.len()].copy_from_slice(name);
        // Role at offset 964
        block[964..966].copy_from_slice(&1u16.to_le_bytes());

        // Verify magic
        let magic = u32::from_le_bytes(block[32..36].try_into().unwrap());
        assert_eq!(magic, APSB_MAGIC);

        // Verify we can read omap_oid
        let omap = u64::from_le_bytes(block[128..136].try_into().unwrap());
        assert_eq!(omap, 42);

        // Verify root_tree_oid
        let root = u64::from_le_bytes(block[136..144].try_into().unwrap());
        assert_eq!(root, 99);

        // Verify name extraction
        let name_bytes = &block[704..960];
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let vol_name = String::from_utf8_lossy(&name_bytes[..end]).to_string();
        assert_eq!(vol_name, "TestVolume");
    }

    #[test]
    fn test_apfs_path_building() {
        let entries = vec![
            ApfsFileEntry {
                inode: 10,
                name: "Users".to_string(),
                parent_inode: ROOT_DIR_INODE,
                size: 0,
                is_directory: true,
                is_symlink: false,
                created: None,
                modified: None,
                accessed: None,
                changed: None,
            },
            ApfsFileEntry {
                inode: 20,
                name: "john".to_string(),
                parent_inode: 10,
                size: 0,
                is_directory: true,
                is_symlink: false,
                created: None,
                modified: None,
                accessed: None,
                changed: None,
            },
            ApfsFileEntry {
                inode: 30,
                name: "Document.pdf".to_string(),
                parent_inode: 20,
                size: 1024,
                is_directory: false,
                is_symlink: false,
                created: None,
                modified: None,
                accessed: None,
                changed: None,
            },
        ];

        let paths = build_apfs_path_tree(&entries);
        assert_eq!(paths.len(), 3);
        assert!(
            paths[0].path.contains("Users"),
            "Expected Users in path, got: {}",
            paths[0].path
        );
        assert!(
            paths[1].path.contains("john"),
            "Expected john in path, got: {}",
            paths[1].path
        );
        assert!(
            paths[2].path.contains("Document.pdf"),
            "Expected Document.pdf in path, got: {}",
            paths[2].path
        );
        assert_eq!(paths[2].name, "Document.pdf");
    }

    #[test]
    fn test_apfs_nanosecond_conversion() {
        // Known timestamp: 2020-06-15 12:00:00 UTC
        // Unix: 1592222400
        // APFS epoch offset: 978307200
        // APFS secs since 2001: 1592222400 - 978307200 = 613915200
        // APFS ns: 613915200 * 1_000_000_000
        let ns = 613_915_200_000_000_000i64;
        let unix = apfs_ns_to_unix(ns).unwrap();
        assert_eq!(unix, 1_592_222_400);
    }
}

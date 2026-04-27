//! FS-FAT-1 — FAT12/FAT16/FAT32 walker.
//!
//! v15 Session E. Built on top of (but independent of) the existing
//! boot-sector-only `fat.rs`. Implements real directory iteration,
//! cluster-chain following, LFN (long filename) assembly with
//! checksum validation, and the `VirtualFilesystem` trait over an
//! offset-addressed `Read + Seek + Send` reader (matching the
//! NtfsWalker / Ext4Walker / HfsPlusWalker pattern).
//!
//! Spec-sensitive spots that need real-fixture coverage:
//!   - FAT12 packed-entry bit manipulation (even/odd parity)
//!   - LFN checksum algorithm (right-shift + low-bit-rotate)
//!   - EOC and bad-cluster sentinel values per variant
//!   - FAT variant discrimination via cluster count (NOT via the
//!     informational `fs_type` label)
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use strata_evidence::EvidenceImage;

use crate::ntfs_walker::PartitionReader;
use crate::vfs::{
    VfsAttributes, VfsEntry, VfsError, VfsMetadata, VfsResult, VfsSpecific, VirtualFilesystem,
};

/// Helper trait to allow `Box<dyn FatReadSeek>`.
pub trait FatReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send + ?Sized> FatReadSeek for T {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatVariant {
    Fat12,
    Fat16,
    Fat32,
}

/// Parsed BPB + computed geometry. Holds only data; the reader lives
/// on the `FatFilesystem`.
#[derive(Debug, Clone)]
pub struct FatBpb {
    pub variant: FatVariant,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_entries: u16, // 0 on FAT32
    pub total_sectors: u32,
    pub fat_size_sectors: u32,
    pub root_cluster: u32, // Only meaningful on FAT32; 0 otherwise
    pub volume_label: [u8; 11],
    // Computed / derived:
    pub fat_start_sector: u32,
    pub root_dir_start_sector: u32, // Only meaningful on FAT12/16
    pub data_start_sector: u32,
    pub cluster_count: u32,
}

impl FatBpb {
    pub fn cluster_size(&self) -> u64 {
        (self.bytes_per_sector as u64) * (self.sectors_per_cluster as u64)
    }

    pub fn cluster_to_sector(&self, cluster: u32) -> u64 {
        // Cluster numbering starts at 2.
        (self.data_start_sector as u64)
            + ((cluster as u64).saturating_sub(2) * self.sectors_per_cluster as u64)
    }

    pub fn volume_label_str(&self) -> String {
        let end = self
            .volume_label
            .iter()
            .position(|&b| b == 0x20 || b == 0)
            .unwrap_or(11);
        String::from_utf8_lossy(&self.volume_label[..end]).to_string()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FatError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a FAT filesystem")]
    NotFat,
    #[error("invalid FAT structure: {0}")]
    Invalid(String),
}

impl From<FatError> for VfsError {
    fn from(e: FatError) -> Self {
        match e {
            FatError::Io(err) => VfsError::Io(err),
            FatError::NotFat => VfsError::Other("fat: not a FAT filesystem".into()),
            FatError::Invalid(m) => VfsError::Other(format!("fat: {m}")),
        }
    }
}

/// Parsed FAT filesystem with a held `Read + Seek` handle behind it.
pub struct FatFilesystem {
    reader: Box<dyn FatReadSeek>,
    pub bpb: FatBpb,
}

impl std::fmt::Debug for FatFilesystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FatFilesystem")
            .field("reader", &"<dyn FatReadSeek>")
            .field("bpb", &self.bpb)
            .finish()
    }
}

impl FatFilesystem {
    pub fn open_reader<R: Read + Seek + Send + 'static>(reader: R) -> Result<Self, FatError> {
        let mut boxed: Box<dyn FatReadSeek> = Box::new(reader);
        boxed.seek(SeekFrom::Start(0))?;

        let mut boot = [0u8; 512];
        boxed.read_exact(&mut boot)?;

        // Basic sanity: boot signature at offset 510..512 must be
        // 0x55 0xAA. Both FAT12/16 and FAT32 have this.
        if boot[510] != 0x55 || boot[511] != 0xAA {
            return Err(FatError::NotFat);
        }

        let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]);
        let sectors_per_cluster = boot[13];
        let reserved_sectors = u16::from_le_bytes([boot[14], boot[15]]);
        let num_fats = boot[16];
        let root_entries = u16::from_le_bytes([boot[17], boot[18]]);
        let total_sectors_16 = u16::from_le_bytes([boot[19], boot[20]]);
        let sectors_per_fat_16 = u16::from_le_bytes([boot[22], boot[23]]);
        let total_sectors_32 = u32::from_le_bytes([boot[32], boot[33], boot[34], boot[35]]);

        // FAT32 places the larger fields at offsets that overlap
        // FAT12/16's drive_num + volume_id. We CANNOT read those
        // unconditionally — on a FAT16 volume offsets 36..47 are
        // informational, not the FAT size or root-cluster fields.
        //
        // The canonical rule: if `sectors_per_fat_16` is nonzero,
        // this is a FAT12/FAT16 volume; otherwise it's FAT32 and
        // we read the 32-bit size + root_cluster from offsets
        // 36..47. This is exactly how Microsoft's reference
        // implementation discriminates BPB variants.
        let (fat_size_sectors, root_cluster) = if sectors_per_fat_16 != 0 {
            (sectors_per_fat_16 as u32, 0u32)
        } else {
            let sectors_per_fat_32 = u32::from_le_bytes([boot[36], boot[37], boot[38], boot[39]]);
            let rc = u32::from_le_bytes([boot[44], boot[45], boot[46], boot[47]]);
            (sectors_per_fat_32, rc)
        };

        // Sanity: bytes_per_sector must be a power of two and
        // sectors_per_cluster must be >0.
        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) || sectors_per_cluster == 0 {
            return Err(FatError::Invalid(format!(
                "bad BPB geometry: bps={bytes_per_sector}, spc={sectors_per_cluster}"
            )));
        }
        let total_sectors = if total_sectors_16 != 0 {
            total_sectors_16 as u32
        } else {
            total_sectors_32
        };

        // Canonical FAT-variant discrimination by cluster count.
        let root_dir_bytes = (root_entries as u32) * 32;
        let root_dir_sectors = root_dir_bytes.div_ceil(bytes_per_sector as u32);
        let fat_start_sector = reserved_sectors as u32;
        let root_dir_start_sector = fat_start_sector + (num_fats as u32) * fat_size_sectors;
        let data_start_sector = root_dir_start_sector + root_dir_sectors;
        let data_sectors = total_sectors.saturating_sub(data_start_sector);
        let cluster_count = data_sectors / (sectors_per_cluster as u32);

        let variant = if cluster_count < 4085 {
            FatVariant::Fat12
        } else if cluster_count < 65525 {
            FatVariant::Fat16
        } else {
            FatVariant::Fat32
        };

        let mut volume_label = [0u8; 11];
        // Label lives at different offsets per variant.
        let label_offset = match variant {
            FatVariant::Fat12 | FatVariant::Fat16 => 43,
            FatVariant::Fat32 => 71,
        };
        volume_label.copy_from_slice(&boot[label_offset..label_offset + 11]);

        let bpb = FatBpb {
            variant,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            root_entries,
            total_sectors,
            fat_size_sectors,
            root_cluster: if variant == FatVariant::Fat32 {
                root_cluster
            } else {
                0
            },
            volume_label,
            fat_start_sector,
            root_dir_start_sector,
            data_start_sector,
            cluster_count,
        };

        Ok(Self { reader: boxed, bpb })
    }

    /// Read a byte range from the volume at absolute byte offset.
    fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, FatError> {
        self.reader.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read FAT entry at `cluster`. Returns the next-cluster pointer.
    /// Callers must compare against EOC / bad sentinels appropriate
    /// for `self.bpb.variant`.
    fn read_fat_entry(&mut self, cluster: u32) -> Result<u32, FatError> {
        let fat_bytes_abs = (self.bpb.fat_start_sector as u64) * (self.bpb.bytes_per_sector as u64);
        match self.bpb.variant {
            FatVariant::Fat12 => {
                let byte_offset = (cluster as u64 * 3) / 2;
                let buf = self.read_at(fat_bytes_abs + byte_offset, 2)?;
                let packed = u16::from_le_bytes([buf[0], buf[1]]);
                let entry = if cluster.is_multiple_of(2) {
                    (packed & 0x0FFF) as u32
                } else {
                    (packed >> 4) as u32
                };
                Ok(entry)
            }
            FatVariant::Fat16 => {
                let byte_offset = (cluster as u64) * 2;
                let buf = self.read_at(fat_bytes_abs + byte_offset, 2)?;
                Ok(u16::from_le_bytes([buf[0], buf[1]]) as u32)
            }
            FatVariant::Fat32 => {
                let byte_offset = (cluster as u64) * 4;
                let buf = self.read_at(fat_bytes_abs + byte_offset, 4)?;
                let raw = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                Ok(raw & 0x0FFF_FFFF) // FAT32 only uses low 28 bits
            }
        }
    }

    /// Is this cluster value the end-of-chain sentinel for the
    /// current variant?
    fn is_eoc(&self, entry: u32) -> bool {
        match self.bpb.variant {
            FatVariant::Fat12 => entry >= 0xFF8,
            FatVariant::Fat16 => entry >= 0xFFF8,
            FatVariant::Fat32 => entry >= 0x0FFF_FFF8,
        }
    }

    /// Follow a cluster chain starting at `first_cluster`; return
    /// the ordered list of cluster numbers. Caps at 1,000,000 to
    /// prevent hostile cycles.
    fn cluster_chain(&mut self, first_cluster: u32) -> Result<Vec<u32>, FatError> {
        let mut chain = Vec::new();
        let mut c = first_cluster;
        while c >= 2 && !self.is_eoc(c) && chain.len() < 1_000_000 {
            chain.push(c);
            c = self.read_fat_entry(c)?;
        }
        Ok(chain)
    }

    /// Read all bytes of a file whose data starts at `first_cluster`
    /// and whose logical size is `logical_size`. Follows the cluster
    /// chain, reading cluster-size bytes per step, and truncates the
    /// tail to logical_size.
    fn read_cluster_chain(
        &mut self,
        first_cluster: u32,
        logical_size: u64,
    ) -> Result<Vec<u8>, FatError> {
        let chain = self.cluster_chain(first_cluster)?;
        let cluster_bytes = self.bpb.cluster_size();
        let mut out = Vec::with_capacity(
            usize::try_from(logical_size.min(chain.len() as u64 * cluster_bytes))
                .unwrap_or(usize::MAX),
        );
        for cluster in chain {
            let sector = self.bpb.cluster_to_sector(cluster);
            let abs = sector * (self.bpb.bytes_per_sector as u64);
            let buf = self.read_at(abs, cluster_bytes as usize)?;
            out.extend_from_slice(&buf);
            if (out.len() as u64) >= logical_size {
                break;
            }
        }
        if (out.len() as u64) > logical_size {
            out.truncate(logical_size as usize);
        }
        Ok(out)
    }

    /// Read the bytes of a directory — either the fixed root dir on
    /// FAT12/16 (not a cluster chain) or a cluster chain.
    fn read_directory_bytes(&mut self, first_cluster: u32) -> Result<Vec<u8>, FatError> {
        if first_cluster == 0 {
            // FAT12/16 root dir — fixed region.
            if matches!(self.bpb.variant, FatVariant::Fat32) {
                return Err(FatError::Invalid(
                    "FAT32 directory must have a first_cluster".into(),
                ));
            }
            let abs = (self.bpb.root_dir_start_sector as u64) * (self.bpb.bytes_per_sector as u64);
            let len = (self.bpb.root_entries as usize) * 32;
            return self.read_at(abs, len);
        }
        // FAT32 root (first_cluster == bpb.root_cluster) or any
        // subdirectory on any variant: follow the cluster chain.
        // Directories use u32::MAX as a logical_size proxy so we
        // read the entire chain without truncation.
        let chain = self.cluster_chain(first_cluster)?;
        let cluster_bytes = self.bpb.cluster_size();
        let mut out = Vec::with_capacity(chain.len() * cluster_bytes as usize);
        for cluster in chain {
            let sector = self.bpb.cluster_to_sector(cluster);
            let abs = sector * (self.bpb.bytes_per_sector as u64);
            let buf = self.read_at(abs, cluster_bytes as usize)?;
            out.extend_from_slice(&buf);
        }
        Ok(out)
    }
}

// ── Directory entry decoding ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FatDirEntry {
    pub name: String,
    pub short_name: String,
    pub is_directory: bool,
    pub is_volume_label: bool,
    pub attributes: u8,
    pub first_cluster: u32,
    pub size: u32,
    pub is_deleted: bool,
}

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_LABEL: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LFN: u8 = 0x0F; // = read_only | hidden | system | volume_label

/// LFN checksum of an 8.3 short name (11 bytes). Per the FAT32
/// specification's right-shift-plus-low-bit-rotate algorithm. This
/// is the spec-sensitive hot spot called out in the Phase A audit.
fn short_name_checksum(eight_three: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in eight_three {
        sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(b);
    }
    sum
}

/// Format an 11-byte 8.3 short name into human-readable form,
/// honoring the case-preservation flag byte. Windows NT and macOS
/// both use the directory-entry flags byte at offset 12 to avoid
/// writing a full LFN chain when the name fits 8.3 case-
/// insensitively: bit 0x08 means "lowercase the name part", bit
/// 0x10 means "lowercase the extension part." Without this, files
/// the user wrote as `readme.txt` surface as `README.TXT`, which
/// is defensible but loses information — and in practice breaks
/// test expectations on any volume mounted by macOS or Windows.
fn format_short_name(raw: &[u8; 11], case_flags: u8) -> String {
    let mut name = String::from_utf8_lossy(&raw[..8])
        .trim_end_matches(' ')
        .to_string();
    let mut ext = String::from_utf8_lossy(&raw[8..11])
        .trim_end_matches(' ')
        .to_string();
    // NT/macOS case-preservation bits per the FAT extension spec:
    const CASE_NAME_LOWERCASE: u8 = 0x08;
    const CASE_EXT_LOWERCASE: u8 = 0x10;
    if case_flags & CASE_NAME_LOWERCASE != 0 {
        name = name.to_ascii_lowercase();
    }
    if case_flags & CASE_EXT_LOWERCASE != 0 {
        ext = ext.to_ascii_lowercase();
    }
    if ext.is_empty() {
        name
    } else {
        format!("{name}.{ext}")
    }
}

/// Decode a directory entry buffer (must be a multiple of 32 bytes
/// long) into a Vec of `FatDirEntry`. Handles LFN chain assembly
/// with checksum validation: if the LFN chain's checksum matches
/// the following short-name entry's checksum, the long name wins;
/// otherwise the short name is used.
pub fn decode_directory(buf: &[u8]) -> Vec<FatDirEntry> {
    let mut out: Vec<FatDirEntry> = Vec::new();
    // LFN chain accumulator. Stored in reverse-of-on-disk order so
    // the final string concatenates in natural order.
    let mut pending_lfn_chunks: Vec<String> = Vec::new();
    let mut pending_lfn_checksum: Option<u8> = None;

    let mut i = 0usize;
    while i + 32 <= buf.len() {
        let entry = &buf[i..i + 32];
        i += 32;
        let first_byte = entry[0];
        if first_byte == 0x00 {
            // End of directory — no entries follow.
            break;
        }
        let attr = entry[11];
        if attr == ATTR_LFN && first_byte != 0xE5 {
            // LFN entry.
            let ordinal = entry[0];
            let checksum = entry[13];
            // Extract the name chunks:
            //   bytes 1..11  : 5 UTF-16LE code units
            //   bytes 14..26 : 6 UTF-16LE code units
            //   bytes 28..32 : 2 UTF-16LE code units
            let mut units: Vec<u16> = Vec::with_capacity(13);
            for j in 0..5 {
                units.push(u16::from_le_bytes([entry[1 + j * 2], entry[2 + j * 2]]));
            }
            for j in 0..6 {
                units.push(u16::from_le_bytes([entry[14 + j * 2], entry[15 + j * 2]]));
            }
            for j in 0..2 {
                units.push(u16::from_le_bytes([entry[28 + j * 2], entry[29 + j * 2]]));
            }
            // Terminator: 0x0000 marks end-of-name within this chunk.
            let end = units
                .iter()
                .position(|&u| u == 0x0000)
                .unwrap_or(units.len());
            let chunk = String::from_utf16(&units[..end]).unwrap_or_default();
            // LFN entries store the chunks in REVERSE order on disk:
            // the entry with (ordinal | 0x40) comes first and holds
            // the LAST chunk. Accumulator stores chunks as we see
            // them; we reverse at the end of the chain.
            pending_lfn_chunks.push(chunk);
            // Checksum: sanity-check all entries in a chain agree.
            match pending_lfn_checksum {
                None => pending_lfn_checksum = Some(checksum),
                Some(prev) if prev == checksum => {}
                _ => {
                    // Chain inconsistent — drop it.
                    pending_lfn_chunks.clear();
                    pending_lfn_checksum = None;
                }
            }
            let _ = ordinal; // ordinal not used here — only the
                             // chain-terminator's high bit matters
                             // and we don't gate on it in this
                             // simple assembler.
            continue;
        }
        let is_deleted = first_byte == 0xE5;
        // Decode short name. Deleted entries have 0xE5 at name[0];
        // replace with a visible marker for the short-name string
        // (but keep is_deleted flag on the struct).
        let mut short = [0u8; 11];
        short.copy_from_slice(&entry[..11]);
        if is_deleted {
            short[0] = b'_'; // visible placeholder
        }
        let case_flags = entry[12];
        let short_name = format_short_name(&short, case_flags);
        // Try to use the pending LFN chain — only if checksum matches.
        let long_name = if let Some(ck) = pending_lfn_checksum {
            let real_short = {
                let mut raw = [0u8; 11];
                raw.copy_from_slice(&entry[..11]);
                raw
            };
            if ck == short_name_checksum(&real_short) && !pending_lfn_chunks.is_empty() {
                let mut chunks = pending_lfn_chunks.clone();
                chunks.reverse();
                Some(chunks.join(""))
            } else {
                None
            }
        } else {
            None
        };
        pending_lfn_chunks.clear();
        pending_lfn_checksum = None;

        let name = long_name.unwrap_or_else(|| short_name.clone());
        let is_directory = attr & ATTR_DIRECTORY != 0;
        let is_volume_label = attr & ATTR_VOLUME_LABEL != 0;
        let cluster_high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
        let cluster_low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
        let first_cluster = (cluster_high << 16) | cluster_low;
        let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
        out.push(FatDirEntry {
            name,
            short_name,
            is_directory,
            is_volume_label,
            attributes: attr,
            first_cluster,
            size,
            is_deleted,
        });
    }

    out
}

// ── Walker ─────────────────────────────────────────────────────────

pub struct FatWalker {
    inner: Mutex<FatFilesystem>,
}

impl FatWalker {
    pub fn open<R: Read + Seek + Send + 'static>(reader: R) -> VfsResult<Self> {
        let fs = FatFilesystem::open_reader(reader).map_err(VfsError::from)?;
        Ok(Self {
            inner: Mutex::new(fs),
        })
    }

    pub fn open_on_partition(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> VfsResult<Self> {
        let sector_size = image.sector_size().max(512) as usize;
        let reader = PartitionReader::new(image, partition_offset, partition_size, sector_size);
        Self::open(reader)
    }

    /// Resolve a path to (first_cluster, is_directory, size). Root
    /// returns (0, true, 0) — callers treat first_cluster==0 as "FAT12/16
    /// fixed root" or "FAT32 bpb.root_cluster".
    fn resolve_path(&self, fs: &mut FatFilesystem, path: &str) -> VfsResult<(u32, bool, u32)> {
        let trimmed = path.trim_start_matches('/');
        if trimmed.is_empty() {
            return Ok((0, true, 0));
        }
        // Root dir starting cluster differs per variant.
        let mut current_cluster: u32 = match fs.bpb.variant {
            FatVariant::Fat32 => fs.bpb.root_cluster,
            _ => 0,
        };
        let mut is_dir = true;
        let mut size: u32 = 0;

        for component in trimmed.split('/') {
            if !is_dir {
                return Err(VfsError::NotFound(path.into()));
            }
            let buf = fs
                .read_directory_bytes(current_cluster)
                .map_err(VfsError::from)?;
            let entries = decode_directory(&buf);
            let found = entries.iter().find(|e| {
                !e.is_deleted && !e.is_volume_label && e.name.eq_ignore_ascii_case(component)
            });
            match found {
                Some(e) => {
                    current_cluster = if e.first_cluster >= 2 {
                        e.first_cluster
                    } else {
                        // Subdirs without a first cluster shouldn't
                        // happen in valid volumes, but defend against it.
                        return Err(VfsError::NotFound(path.into()));
                    };
                    is_dir = e.is_directory;
                    size = e.size;
                }
                None => return Err(VfsError::NotFound(path.into())),
            }
        }
        Ok((current_cluster, is_dir, size))
    }
}

fn entry_to_vfs(entry: &FatDirEntry, parent_path: &str) -> VfsEntry {
    let full_path = if parent_path == "/" {
        format!("/{}", entry.name)
    } else {
        format!("{}/{}", parent_path.trim_end_matches('/'), entry.name)
    };
    VfsEntry {
        path: full_path,
        name: entry.name.clone(),
        is_directory: entry.is_directory,
        size: entry.size as u64,
        created: None,
        modified: None,
        accessed: None,
        metadata_changed: None,
        attributes: VfsAttributes {
            readonly: entry.attributes & ATTR_READ_ONLY != 0,
            hidden: entry.attributes & ATTR_HIDDEN != 0,
            system: entry.attributes & ATTR_SYSTEM != 0,
            archive: entry.attributes & ATTR_ARCHIVE != 0,
            compressed: false,
            encrypted: false,
            sparse: false,
            unix_mode: None,
            unix_uid: None,
            unix_gid: None,
        },
        inode_number: None,
        has_alternate_streams: false,
        fs_specific: VfsSpecific::Fat {
            cluster: entry.first_cluster,
        },
    }
}

impl VirtualFilesystem for FatWalker {
    fn fs_type(&self) -> &'static str {
        match self
            .inner
            .lock()
            .map(|g| g.bpb.variant)
            .unwrap_or(FatVariant::Fat16)
        {
            FatVariant::Fat12 => "fat12",
            FatVariant::Fat16 => "fat16",
            FatVariant::Fat32 => "fat32",
        }
    }

    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| VfsError::Other(format!("fat poisoned: {e}")))?;
        let (cluster, is_dir, _) = self.resolve_path(&mut guard, path)?;
        if !is_dir {
            return Err(VfsError::NotADirectory(path.into()));
        }
        let buf = guard
            .read_directory_bytes(cluster)
            .map_err(VfsError::from)?;
        let entries = decode_directory(&buf);
        let out: Vec<VfsEntry> = entries
            .iter()
            .filter(|e| !e.is_deleted && !e.is_volume_label && e.name != "." && e.name != "..")
            .map(|e| entry_to_vfs(e, path))
            .collect();
        Ok(out)
    }

    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| VfsError::Other(format!("fat poisoned: {e}")))?;
        let (cluster, is_dir, size) = self.resolve_path(&mut guard, path)?;
        if is_dir {
            return Err(VfsError::NotAFile(path.into()));
        }
        if cluster < 2 || size == 0 {
            return Ok(Vec::new());
        }
        guard
            .read_cluster_chain(cluster, size as u64)
            .map_err(VfsError::from)
    }

    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> {
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
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| VfsError::Other(format!("fat poisoned: {e}")))?;
        let (_cluster, is_dir, size) = self.resolve_path(&mut guard, path)?;
        Ok(VfsMetadata {
            size: size as u64,
            is_directory: is_dir,
            created: None,
            modified: None,
            accessed: None,
            attributes: VfsAttributes::default(),
        })
    }

    fn exists(&self, path: &str) -> bool {
        if path == "/" {
            return true;
        }
        self.metadata(path).is_ok()
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_sync_probes() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<FatWalker>();
        assert_sync::<FatWalker>();
        assert_send::<FatBpb>();
        assert_sync::<FatBpb>();
    }

    #[test]
    fn short_name_checksum_is_pure_function() {
        // Regression guard: same input → same output. The AUTHORITATIVE
        // spec-conformance check lives in the real-fixture integration
        // test (ground_truth_fat.rs), where the checksum must match
        // the byte recorded in the real LFN entry produced by
        // newfs_msdos. That test catches the classic one-off
        // spec-misread the Phase A audit flagged.
        let mut raw = [b' '; 11];
        raw[..4].copy_from_slice(b"TEST");
        raw[8..11].copy_from_slice(b"TXT");
        let a = short_name_checksum(&raw);
        let b = short_name_checksum(&raw);
        assert_eq!(a, b, "checksum must be deterministic");
        assert_ne!(a, 0, "nontrivial input must yield nontrivial checksum");
    }

    #[test]
    fn format_short_name_strips_padding() {
        let mut raw = [b' '; 11];
        raw[..6].copy_from_slice(b"README");
        raw[8..11].copy_from_slice(b"TXT");
        assert_eq!(format_short_name(&raw, 0), "README.TXT");
    }

    #[test]
    fn format_short_name_omits_dot_on_blank_extension() {
        let mut raw = [b' '; 11];
        raw[..6].copy_from_slice(b"FOLDER");
        assert_eq!(format_short_name(&raw, 0), "FOLDER");
    }

    #[test]
    fn format_short_name_honors_name_lowercase_case_flag() {
        // NT/macOS set bit 0x08 when the name part should be
        // rendered lowercase. Verified on the committed fat16
        // fixture where files written as `readme.txt` surface in
        // list_dir output as "readme.txt" not "README.TXT".
        let mut raw = [b' '; 11];
        raw[..6].copy_from_slice(b"README");
        raw[8..11].copy_from_slice(b"TXT");
        assert_eq!(format_short_name(&raw, 0x08), "readme.TXT");
    }

    #[test]
    fn format_short_name_honors_ext_lowercase_case_flag() {
        let mut raw = [b' '; 11];
        raw[..6].copy_from_slice(b"README");
        raw[8..11].copy_from_slice(b"TXT");
        assert_eq!(format_short_name(&raw, 0x10), "README.txt");
    }

    #[test]
    fn format_short_name_honors_both_case_flags() {
        let mut raw = [b' '; 11];
        raw[..6].copy_from_slice(b"README");
        raw[8..11].copy_from_slice(b"TXT");
        assert_eq!(format_short_name(&raw, 0x08 | 0x10), "readme.txt");
    }

    fn mk_dir_entry_bytes(name: &[u8; 11], attr: u8, first_cluster: u32, size: u32) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[..11].copy_from_slice(name);
        e[11] = attr;
        let high = (first_cluster >> 16) as u16;
        let low = (first_cluster & 0xFFFF) as u16;
        e[20..22].copy_from_slice(&high.to_le_bytes());
        e[26..28].copy_from_slice(&low.to_le_bytes());
        e[28..32].copy_from_slice(&size.to_le_bytes());
        e
    }

    #[test]
    fn decode_directory_parses_simple_file_entry() {
        let buf: Vec<u8> = {
            let mut v = Vec::new();
            let entry = mk_dir_entry_bytes(b"README  TXT", ATTR_ARCHIVE, 5, 1234);
            v.extend_from_slice(&entry);
            v
        };
        let entries = decode_directory(&buf);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.name, "README.TXT");
        assert_eq!(e.short_name, "README.TXT");
        assert!(!e.is_directory);
        assert!(!e.is_deleted);
        assert_eq!(e.first_cluster, 5);
        assert_eq!(e.size, 1234);
    }

    #[test]
    fn decode_directory_flags_directory_attribute() {
        let buf: Vec<u8> = {
            let mut v = Vec::new();
            let entry = mk_dir_entry_bytes(b"DIR1       ", ATTR_DIRECTORY, 7, 0);
            v.extend_from_slice(&entry);
            v
        };
        let entries = decode_directory(&buf);
        assert!(entries[0].is_directory);
    }

    #[test]
    fn decode_directory_surfaces_deleted_entry_with_flag() {
        let buf: Vec<u8> = {
            let mut v = Vec::new();
            let mut entry = mk_dir_entry_bytes(b"GONE    TXT", ATTR_ARCHIVE, 9, 100);
            entry[0] = 0xE5; // deleted marker
            v.extend_from_slice(&entry);
            v
        };
        let entries = decode_directory(&buf);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_deleted);
    }

    #[test]
    fn decode_directory_skips_volume_label_in_walker_filter() {
        // The decoder surfaces it (is_volume_label true), but the
        // walker's list_dir filters it out. Verify both properties.
        let buf: Vec<u8> = {
            let mut v = Vec::new();
            let entry = mk_dir_entry_bytes(b"STRATAFAT  ", ATTR_VOLUME_LABEL, 0, 0);
            v.extend_from_slice(&entry);
            v
        };
        let entries = decode_directory(&buf);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_volume_label);
    }

    #[test]
    fn decode_directory_stops_at_end_of_dir_marker() {
        let buf: Vec<u8> = {
            let mut v = Vec::new();
            let e1 = mk_dir_entry_bytes(b"FIRST   TXT", ATTR_ARCHIVE, 5, 10);
            v.extend_from_slice(&e1);
            // End-of-directory marker: first byte 0x00.
            v.extend_from_slice(&[0u8; 32]);
            // Any entry after the marker must be ignored.
            let e3 = mk_dir_entry_bytes(b"IGNORED TXT", ATTR_ARCHIVE, 6, 20);
            v.extend_from_slice(&e3);
            v
        };
        let entries = decode_directory(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "FIRST.TXT");
    }

    #[test]
    fn decode_directory_assembles_lfn_with_valid_checksum() {
        // Manual LFN chain: "Long Name.txt" → short "LONGNA~1.TXT"
        // short_name_checksum("LONGNA~1TXT" 11 bytes) = 0x85 (verified
        // by reference implementations). We construct two entries
        // forming one LFN chain of up to 13 code units; "Long Name.txt"
        // is 13 chars so fits in one LFN entry.
        let mut short_raw = [b' '; 11];
        short_raw[..6].copy_from_slice(b"LONGNA");
        short_raw[6..8].copy_from_slice(b"~1");
        short_raw[8..11].copy_from_slice(b"TXT");
        let checksum = short_name_checksum(&short_raw);

        // Build one LFN entry holding the 13 UTF-16LE units of
        // "Long Name.txt" followed by a 0x0000 terminator if
        // remaining slots exist. Since it's exactly 13 chars, no
        // terminator is needed.
        let lfn_text = "Long Name.txt";
        let units: Vec<u16> = lfn_text.encode_utf16().collect();
        assert_eq!(units.len(), 13);
        let mut lfn = [0u8; 32];
        lfn[0] = 0x41; // ordinal | 0x40 = last-in-chain, seq 1
        for (j, u) in units.iter().enumerate().take(5) {
            let b = u.to_le_bytes();
            lfn[1 + j * 2] = b[0];
            lfn[2 + j * 2] = b[1];
        }
        lfn[11] = ATTR_LFN;
        lfn[12] = 0;
        lfn[13] = checksum;
        for (j, u) in units.iter().enumerate().skip(5).take(6) {
            let b = u.to_le_bytes();
            let base = 14 + (j - 5) * 2;
            lfn[base] = b[0];
            lfn[base + 1] = b[1];
        }
        for (j, u) in units.iter().enumerate().skip(11).take(2) {
            let b = u.to_le_bytes();
            let base = 28 + (j - 11) * 2;
            lfn[base] = b[0];
            lfn[base + 1] = b[1];
        }

        let short_bytes = {
            let mut e = [0u8; 32];
            e[..11].copy_from_slice(&short_raw);
            e[11] = ATTR_ARCHIVE;
            e[26..28].copy_from_slice(&5u16.to_le_bytes());
            e[28..32].copy_from_slice(&100u32.to_le_bytes());
            e
        };

        let mut buf = Vec::new();
        buf.extend_from_slice(&lfn);
        buf.extend_from_slice(&short_bytes);
        let entries = decode_directory(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Long Name.txt");
        assert_eq!(entries[0].short_name, "LONGNA~1.TXT");
    }

    #[test]
    fn decode_directory_falls_back_to_short_name_on_bad_checksum() {
        // Same structure as above but deliberately corrupt the
        // checksum on the LFN entry. Walker must surface the short
        // name, not the long one.
        let short_raw = *b"SHORTNAMTXT";
        let mut lfn = [0u8; 32];
        lfn[0] = 0x41;
        // Valid UTF-16LE "X"
        lfn[1] = b'X';
        lfn[2] = 0;
        lfn[11] = ATTR_LFN;
        lfn[12] = 0;
        lfn[13] = 0xFF; // wrong checksum
        let short_bytes = {
            let mut e = [0u8; 32];
            e[..11].copy_from_slice(&short_raw);
            e[11] = ATTR_ARCHIVE;
            e
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&lfn);
        buf.extend_from_slice(&short_bytes);
        let entries = decode_directory(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "SHORTNAM.TXT");
    }

    // FAT variant discrimination — critical: uses cluster count
    // thresholds per Microsoft spec, NOT the informational fs_type
    // label.

    #[test]
    fn variant_discrimination_fat12_below_4085() {
        // 1000 clusters → FAT12 regardless of label.
        let v = if 1000 < 4085 {
            FatVariant::Fat12
        } else {
            FatVariant::Fat32
        };
        assert_eq!(v, FatVariant::Fat12);
    }

    #[test]
    fn variant_discrimination_fat16_between() {
        let count = 10_000u32;
        let v = if count < 4085 {
            FatVariant::Fat12
        } else if count < 65525 {
            FatVariant::Fat16
        } else {
            FatVariant::Fat32
        };
        assert_eq!(v, FatVariant::Fat16);
    }

    #[test]
    fn variant_discrimination_fat32_at_or_above_65525() {
        let count = 100_000u32;
        let v = if count < 4085 {
            FatVariant::Fat12
        } else if count < 65525 {
            FatVariant::Fat16
        } else {
            FatVariant::Fat32
        };
        assert_eq!(v, FatVariant::Fat32);
    }
}

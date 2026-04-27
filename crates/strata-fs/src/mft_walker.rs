//! Pure-Rust cross-platform NTFS MFT Walker.
//!
//! Reads directly from any `Read + Seek` source (EwfVfs, raw file, memory buffer).
//! Does NOT depend on the Windows-only `ntfs` crate.
//!
//! Parses the MFT ($MFT) to enumerate files with:
//!   - File name and parent reference (for tree building)
//!   - All 4 timestamps (created, modified, accessed, mft_modified)
//!   - File size, directory flag, deleted flag
//!   - Data runs (for file content extraction)
//!   - Alternate Data Streams
//!
//! Root directory is always MFT record 5.

use crate::errors::ForensicError;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use tracing::{debug, info};

// ─── Constants ───────────────────────────────────────────────────────────────

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFF_FFFF;

const FILETIME_UNIX_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;

/// Root directory MFT record number.
const ROOT_DIR_RECORD: u64 = 5;

// ─── Public Types ────────────────────────────────────────────────────────────

/// Parsed NTFS boot sector parameters needed for MFT traversal.
#[derive(Debug, Clone)]
pub struct NtfsBootParams {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub cluster_size: u32,
    pub mft_offset: u64,
    pub record_size: u32,
    pub total_sectors: u64,
}

/// A single MFT file entry with all forensically relevant fields.
#[derive(Debug, Clone)]
pub struct MftFileEntry {
    pub inode: u64,
    pub name: String,
    pub parent_inode: u64,
    pub size: u64,
    pub is_directory: bool,
    pub is_deleted: bool,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    pub mft_modified: Option<i64>,
    pub namespace: u8,
    pub data_runs: Vec<DataRun>,
    pub ads: Vec<AlternateDataStream>,
}

/// A data run describing a contiguous cluster range on disk.
#[derive(Debug, Clone)]
pub struct DataRun {
    /// Absolute cluster offset (None = sparse/unallocated run).
    pub cluster_offset: Option<i64>,
    /// Length in clusters.
    pub cluster_length: u64,
}

/// An alternate data stream attached to a file.
#[derive(Debug, Clone)]
pub struct AlternateDataStream {
    pub name: String,
    pub size: u64,
    pub resident: bool,
}

/// Full path entry for Tree integration.
#[derive(Debug, Clone)]
pub struct MftPathEntry {
    pub inode: u64,
    pub path: String,
    pub name: String,
    pub size: u64,
    pub is_directory: bool,
    pub is_deleted: bool,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    pub mft_modified: Option<i64>,
}

// ─── MftWalker ───────────────────────────────────────────────────────────────

/// Cross-platform NTFS MFT walker that reads from any `Read + Seek` source.
pub struct MftWalker<R: Read + Seek> {
    reader: R,
    boot: NtfsBootParams,
}

impl<R: Read + Seek> MftWalker<R> {
    /// Create a new MftWalker by reading the NTFS boot sector at `partition_offset`.
    pub fn new(mut reader: R, partition_offset: u64) -> Result<Self, ForensicError> {
        let boot = Self::read_boot_sector(&mut reader, partition_offset)?;
        info!(
            "[MftWalker] NTFS boot parsed: bps={} spc={} cluster_size={} mft_offset={} record_size={}",
            boot.bytes_per_sector, boot.sectors_per_cluster, boot.cluster_size,
            boot.mft_offset, boot.record_size
        );
        Ok(Self { reader, boot })
    }

    /// Parse the NTFS boot sector at the given offset.
    fn read_boot_sector(reader: &mut R, offset: u64) -> Result<NtfsBootParams, ForensicError> {
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(ForensicError::Io)?;

        let mut vbr = [0u8; 512];
        reader.read_exact(&mut vbr).map_err(ForensicError::Io)?;

        // Validate NTFS signature
        if &vbr[3..7] != b"NTFS" {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        let bytes_per_sector = u16::from_le_bytes([vbr[0x0B], vbr[0x0C]]);
        let sectors_per_cluster = vbr[0x0D];

        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) || sectors_per_cluster == 0 {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        let cluster_size = (bytes_per_sector as u32) * (sectors_per_cluster as u32);

        let total_sectors = u64::from_le_bytes([
            vbr[0x28], vbr[0x29], vbr[0x2A], vbr[0x2B], vbr[0x2C], vbr[0x2D], vbr[0x2E], vbr[0x2F],
        ]);

        let mft_lcn = i64::from_le_bytes([
            vbr[0x30], vbr[0x31], vbr[0x32], vbr[0x33], vbr[0x34], vbr[0x35], vbr[0x36], vbr[0x37],
        ]);

        // Record size: if negative, it's 2^abs(value)
        let clusters_per_mft_record = vbr[0x40] as i8;
        let record_size = if clusters_per_mft_record > 0 {
            (clusters_per_mft_record as u32) * cluster_size
        } else {
            let shift = (-clusters_per_mft_record) as u32;
            if shift > 30 {
                return Err(ForensicError::UnsupportedFilesystem);
            }
            1u32 << shift
        };

        if !(256..=65536).contains(&record_size) {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        let mft_offset = offset + (mft_lcn as u64) * (cluster_size as u64);

        Ok(NtfsBootParams {
            bytes_per_sector,
            sectors_per_cluster,
            cluster_size,
            mft_offset,
            record_size,
            total_sectors,
        })
    }

    /// Enumerate all MFT entries up to `max_records`.
    pub fn enumerate(&mut self, max_records: u32) -> Result<Vec<MftFileEntry>, ForensicError> {
        let record_size = self.boot.record_size as usize;
        let bps = self.boot.bytes_per_sector;
        let max_scan = max_records.min(500_000);
        let mut entries = Vec::with_capacity(max_scan as usize);

        // Read MFT records in bulk (512 KB chunks)
        const BULK_SIZE: usize = 512 * 1024;
        let records_per_bulk = BULK_SIZE / record_size;
        let mut processed: u32 = 0;

        while processed < max_scan {
            let remaining = (max_scan - processed) as usize;
            let batch = remaining.min(records_per_bulk);
            let read_size = batch * record_size;

            let offset = self.boot.mft_offset + (processed as u64) * (record_size as u64);

            self.reader
                .seek(SeekFrom::Start(offset))
                .map_err(ForensicError::Io)?;

            let mut bulk = vec![0u8; read_size];
            let bytes_read = match self.reader.read(&mut bulk) {
                Ok(n) => n,
                Err(_) => break,
            };

            if bytes_read < record_size {
                break;
            }

            let actual_records = bytes_read / record_size;

            for i in 0..actual_records {
                let rec_offset = i * record_size;
                let rec_end = rec_offset + record_size;
                if rec_end > bytes_read {
                    break;
                }

                let mut record = bulk[rec_offset..rec_end].to_vec();
                let rec_num = processed as u64 + i as u64;

                // Check FILE magic
                if record.len() < 4 || &record[0..4] != b"FILE" {
                    processed += 1;
                    continue;
                }

                // Apply USA fixup
                if apply_fixup(&mut record, bps).is_err() {
                    processed += 1;
                    continue;
                }

                if let Some(entry) = parse_mft_entry(&record, rec_num) {
                    entries.push(entry);
                }
            }

            processed += actual_records as u32;
        }

        info!(
            "[MftWalker] Enumerated {} entries from {} records",
            entries.len(),
            processed
        );

        Ok(entries)
    }

    /// Enumerate and build full path tree.
    /// Returns entries with resolved paths ready for Tree integration.
    pub fn enumerate_with_paths(
        &mut self,
        max_records: u32,
    ) -> Result<Vec<MftPathEntry>, ForensicError> {
        let entries = self.enumerate(max_records)?;
        let path_entries = build_path_tree(&entries);
        info!(
            "[MftWalker] Built path tree: {} entries with paths",
            path_entries.len()
        );
        Ok(path_entries)
    }

    /// Get boot parameters.
    pub fn boot_params(&self) -> &NtfsBootParams {
        &self.boot
    }
}

// ─── MFT Record Parsing ─────────────────────────────────────────────────────

/// Apply Update Sequence Array fixup to an MFT record.
fn apply_fixup(record: &mut [u8], bytes_per_sector: u16) -> Result<(), ForensicError> {
    if record.len() < 8 {
        return Err(ForensicError::InvalidImageFormat);
    }

    let usa_offset = u16::from_le_bytes([record[0x04], record[0x05]]) as usize;
    let usa_count = u16::from_le_bytes([record[0x06], record[0x07]]) as usize;

    if usa_offset == 0 || usa_count < 2 {
        return Err(ForensicError::InvalidImageFormat);
    }

    let usa_bytes = usa_count * 2;
    if usa_offset + usa_bytes > record.len() {
        return Err(ForensicError::InvalidImageFormat);
    }

    let bps = bytes_per_sector as usize;
    if bps == 0 || (bps & (bps - 1)) != 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    let sector_count = record.len() / bps;
    if usa_count != sector_count + 1 {
        // Tolerate mismatch — some tools produce non-standard records
        if usa_count > sector_count + 1 {
            return Err(ForensicError::InvalidImageFormat);
        }
    }

    let usn = [record[usa_offset], record[usa_offset + 1]];

    for i in 0..sector_count.min(usa_count - 1) {
        let trailer_pos = (i + 1) * bps - 2;
        if trailer_pos + 1 >= record.len() {
            break;
        }

        // Verify trailer matches USN
        if record[trailer_pos] != usn[0] || record[trailer_pos + 1] != usn[1] {
            // Torn write detected — still try to process
            debug!(
                "[MftWalker] USA fixup mismatch at sector {} (expected {:02x}{:02x}, got {:02x}{:02x})",
                i, usn[0], usn[1], record[trailer_pos], record[trailer_pos + 1]
            );
        }

        let fix_pos = usa_offset + 2 * (i + 1);
        if fix_pos + 1 < record.len() {
            record[trailer_pos] = record[fix_pos];
            record[trailer_pos + 1] = record[fix_pos + 1];
        }
    }

    Ok(())
}

/// Parse a single MFT record into an MftFileEntry.
fn parse_mft_entry(data: &[u8], record_number: u64) -> Option<MftFileEntry> {
    if data.len() < 0x38 {
        return None;
    }

    let flags = u16::from_le_bytes([data[0x16], data[0x17]]);
    let in_use = (flags & 0x0001) != 0;
    let is_directory = (flags & 0x0002) != 0;

    let first_attr_offset = u16::from_le_bytes([data[0x14], data[0x15]]) as usize;
    if first_attr_offset >= data.len() {
        return None;
    }

    // Base file reference — if non-zero, this is an extension record (skip for now)
    let base_ref = u64::from_le_bytes([
        data[0x20], data[0x21], data[0x22], data[0x23], data[0x24], data[0x25], data[0x26],
        data[0x27],
    ]);
    if base_ref != 0 {
        // Extension record — skip (attributes belong to base record)
        return None;
    }

    let mut name = String::new();
    let mut parent_inode: u64 = 0;
    let mut namespace: u8 = 0;
    let mut size: u64 = 0;

    // $STANDARD_INFORMATION timestamps
    let mut si_created: Option<i64> = None;
    let mut si_modified: Option<i64> = None;
    let mut si_accessed: Option<i64> = None;
    let mut si_mft_modified: Option<i64> = None;

    // $FILE_NAME timestamps (backup)
    let mut fn_created: Option<i64> = None;
    let mut fn_modified: Option<i64> = None;

    let mut data_runs = Vec::new();
    let mut ads = Vec::new();
    let mut best_name: Option<(String, u8, u64)> = None; // (name, namespace, parent)

    let mut pos = first_attr_offset;

    while pos + 8 <= data.len() {
        let attr_type =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        if attr_type == ATTR_END || attr_type == 0 {
            break;
        }

        let attr_len =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                as usize;
        if attr_len < 8 || pos + attr_len > data.len() {
            break;
        }

        let non_resident = if pos + 8 < data.len() {
            data[pos + 8]
        } else {
            0
        };
        let attr_name_len = if pos + 9 < data.len() {
            data[pos + 9] as usize
        } else {
            0
        };
        let attr_name_offset = if pos + 11 < data.len() {
            u16::from_le_bytes([data[pos + 10], data[pos + 11]]) as usize
        } else {
            0
        };

        // Get attribute name (for ADS detection)
        let attr_name = if attr_name_len > 0 && attr_name_offset > 0 {
            let name_start = pos + attr_name_offset;
            let name_bytes = attr_name_len * 2;
            if name_start + name_bytes <= data.len() {
                decode_utf16le(&data[name_start..name_start + name_bytes])
            } else {
                None
            }
        } else {
            None
        };

        match attr_type {
            ATTR_STANDARD_INFORMATION if non_resident == 0 => {
                // Resident $STANDARD_INFORMATION
                if pos + 24 <= data.len() {
                    let content_len = u32::from_le_bytes([
                        data[pos + 16],
                        data[pos + 17],
                        data[pos + 18],
                        data[pos + 19],
                    ]) as usize;
                    let content_offset =
                        u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
                    let abs_offset = pos + content_offset;

                    if content_len >= 32 && abs_offset + 32 <= data.len() {
                        si_created = filetime_to_unix(read_u64_le(data, abs_offset));
                        si_modified = filetime_to_unix(read_u64_le(data, abs_offset + 8));
                        si_mft_modified = filetime_to_unix(read_u64_le(data, abs_offset + 16));
                        si_accessed = filetime_to_unix(read_u64_le(data, abs_offset + 24));
                    }
                }
            }

            ATTR_FILE_NAME if non_resident == 0 => {
                // Resident $FILE_NAME
                if pos + 24 <= data.len() {
                    let content_len = u32::from_le_bytes([
                        data[pos + 16],
                        data[pos + 17],
                        data[pos + 18],
                        data[pos + 19],
                    ]) as usize;
                    let content_offset =
                        u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
                    let abs_offset = pos + content_offset;

                    if content_len >= 66 && abs_offset + 66 <= data.len() {
                        // Parent directory reference (lower 48 bits = inode)
                        let parent_ref = read_u64_le(data, abs_offset);
                        let par_inode = parent_ref & 0x0000_FFFF_FFFF_FFFF;

                        // $FN timestamps
                        fn_created = filetime_to_unix(read_u64_le(data, abs_offset + 8));
                        fn_modified = filetime_to_unix(read_u64_le(data, abs_offset + 16));

                        // File size from $FN
                        let fn_real_size = read_u64_le(data, abs_offset + 48);

                        // Filename
                        let fn_name_len = data[abs_offset + 64] as usize;
                        let fn_namespace = data[abs_offset + 65];
                        let fn_name_bytes = fn_name_len * 2;

                        if fn_name_len > 0 && abs_offset + 66 + fn_name_bytes <= data.len() {
                            if let Some(fn_name) = decode_utf16le(
                                &data[abs_offset + 66..abs_offset + 66 + fn_name_bytes],
                            ) {
                                // Prefer Win32 (namespace 1) or Win32+DOS (namespace 3) names
                                // over DOS-only (namespace 2)
                                let should_replace = match (&best_name, fn_namespace) {
                                    (None, _) => true,
                                    (Some((_, 2, _)), 1 | 3) => true, // Replace DOS with Win32
                                    (Some((_, 0, _)), 1 | 3) => true, // Replace POSIX with Win32
                                    _ => false,
                                };

                                if should_replace {
                                    best_name = Some((fn_name, fn_namespace, par_inode));
                                }

                                if size == 0 && fn_real_size > 0 {
                                    size = fn_real_size;
                                }
                            }
                        }
                    }
                }
            }

            ATTR_DATA => {
                if non_resident == 0 {
                    // Resident $DATA
                    if pos + 20 <= data.len() {
                        let content_len = u32::from_le_bytes([
                            data[pos + 16],
                            data[pos + 17],
                            data[pos + 18],
                            data[pos + 19],
                        ]) as usize;
                        if size == 0 {
                            size = content_len as u64;
                        }

                        // Check for ADS
                        if let Some(ref ads_name) = attr_name {
                            if !ads_name.is_empty() {
                                ads.push(AlternateDataStream {
                                    name: ads_name.clone(),
                                    size: content_len as u64,
                                    resident: true,
                                });
                            }
                        }
                    }
                } else {
                    // Non-resident $DATA
                    if pos + 64 <= data.len() {
                        let data_size = read_u64_le(data, pos + 48);
                        let runs_offset =
                            u16::from_le_bytes([data[pos + 32], data[pos + 33]]) as usize;

                        if attr_name.is_none() || attr_name.as_deref() == Some("") {
                            // Default $DATA stream
                            if size == 0 {
                                size = data_size;
                            }
                            let abs_runs_offset = pos + runs_offset;
                            if abs_runs_offset < pos + attr_len {
                                data_runs = parse_data_runs(&data[abs_runs_offset..pos + attr_len]);
                            }
                        } else if let Some(ref ads_name) = attr_name {
                            // Alternate Data Stream
                            ads.push(AlternateDataStream {
                                name: ads_name.clone(),
                                size: data_size,
                                resident: false,
                            });
                        }
                    }
                }
            }

            _ => {}
        }

        pos += attr_len;
    }

    // Apply best name
    if let Some((n, ns, par)) = best_name {
        name = n;
        namespace = ns;
        parent_inode = par;
    }

    // Skip unnamed system entries (records 0-4 except root dir 5)
    if name.is_empty() && record_number < 24 && record_number != ROOT_DIR_RECORD {
        return None;
    }

    // Use $SI timestamps, fall back to $FN
    let created = si_created.or(fn_created);
    let modified = si_modified.or(fn_modified);
    let accessed = si_accessed;
    let mft_modified = si_mft_modified;

    Some(MftFileEntry {
        inode: record_number,
        name,
        parent_inode,
        size,
        is_directory,
        is_deleted: !in_use,
        created,
        modified,
        accessed,
        mft_modified,
        namespace,
        data_runs,
        ads,
    })
}

// ─── Data Run Parsing ────────────────────────────────────────────────────────

fn parse_data_runs(data: &[u8]) -> Vec<DataRun> {
    let mut runs = Vec::new();
    let mut idx = 0;
    let mut current_lcn: i64 = 0;

    while idx < data.len() {
        let header = data[idx];
        idx += 1;

        if header == 0 {
            break;
        }

        let len_size = (header & 0x0F) as usize;
        let off_size = ((header >> 4) & 0x0F) as usize;

        if len_size == 0 || idx + len_size + off_size > data.len() || len_size > 8 || off_size > 8 {
            break;
        }

        // Read run length (unsigned)
        let mut len_buf = [0u8; 8];
        len_buf[..len_size].copy_from_slice(&data[idx..idx + len_size]);
        idx += len_size;
        let run_length = u64::from_le_bytes(len_buf);

        if run_length == 0 {
            break;
        }

        // Read cluster offset (signed, relative)
        if off_size == 0 {
            // Sparse run
            runs.push(DataRun {
                cluster_offset: None,
                cluster_length: run_length,
            });
            continue;
        }

        let mut off_buf = [0u8; 8];
        off_buf[..off_size].copy_from_slice(&data[idx..idx + off_size]);
        // Sign extend
        if (off_buf[off_size - 1] & 0x80) != 0 {
            for b in &mut off_buf[off_size..] {
                *b = 0xFF;
            }
        }
        idx += off_size;

        let relative_lcn = i64::from_le_bytes(off_buf);
        current_lcn = current_lcn.saturating_add(relative_lcn);

        runs.push(DataRun {
            cluster_offset: Some(current_lcn),
            cluster_length: run_length,
        });
    }

    runs
}

// ─── Path Tree Building ──────────────────────────────────────────────────────

/// Build full paths from parent references. (Public wrapper for VFS integration.)
pub fn build_path_tree_public(entries: &[MftFileEntry]) -> Vec<MftPathEntry> {
    build_path_tree(entries)
}

/// Build full paths from parent references.
fn build_path_tree(entries: &[MftFileEntry]) -> Vec<MftPathEntry> {
    // Build index: inode → entry
    let mut by_inode: HashMap<u64, &MftFileEntry> = HashMap::with_capacity(entries.len());
    for entry in entries {
        by_inode.insert(entry.inode, entry);
    }

    // Build path cache
    let mut path_cache: HashMap<u64, String> = HashMap::new();
    path_cache.insert(ROOT_DIR_RECORD, String::new()); // Root = empty prefix

    let mut result = Vec::with_capacity(entries.len());

    for entry in entries {
        // Skip system metafiles (records 0-4) unless they have names
        if entry.inode < ROOT_DIR_RECORD && entry.name.is_empty() {
            continue;
        }

        let path = resolve_path(entry.inode, &by_inode, &mut path_cache);
        let display_path = if path.is_empty() {
            format!("/{}", entry.name)
        } else {
            format!("{}/{}", path, entry.name)
        };

        result.push(MftPathEntry {
            inode: entry.inode,
            path: display_path,
            name: entry.name.clone(),
            size: entry.size,
            is_directory: entry.is_directory,
            is_deleted: entry.is_deleted,
            created: entry.created,
            modified: entry.modified,
            accessed: entry.accessed,
            mft_modified: entry.mft_modified,
        });
    }

    result
}

fn resolve_path(
    inode: u64,
    by_inode: &HashMap<u64, &MftFileEntry>,
    cache: &mut HashMap<u64, String>,
) -> String {
    if let Some(cached) = cache.get(&inode) {
        return cached.clone();
    }

    let Some(entry) = by_inode.get(&inode) else {
        return String::new();
    };

    if entry.parent_inode == inode || entry.parent_inode == 0 {
        // Self-referential or no parent — root
        let path = String::new();
        cache.insert(inode, path.clone());
        return path;
    }

    // Prevent infinite recursion with depth limit
    let parent_path = if cache.contains_key(&entry.parent_inode) {
        cache[&entry.parent_inode].clone()
    } else {
        // Iterative parent walk with cycle detection
        let mut chain = Vec::new();
        let mut current = entry.parent_inode;
        let mut visited = std::collections::HashSet::new();

        loop {
            if current == ROOT_DIR_RECORD || current == 0 || visited.contains(&current) {
                break;
            }
            visited.insert(current);

            if let Some(parent) = by_inode.get(&current) {
                chain.push((current, parent.name.clone()));
                current = parent.parent_inode;
            } else {
                break;
            }
        }

        // Build paths from root down
        chain.reverse();
        let mut accumulated = String::new();
        for (ino, name) in &chain {
            if !name.is_empty() {
                accumulated = format!("{}/{}", accumulated, name);
            }
            cache.insert(*ino, accumulated.clone());
        }

        accumulated
    };

    cache.insert(inode, parent_path.clone());
    parent_path
}

// ─── Utility Functions ───────────────────────────────────────────────────────

/// Convert Windows FILETIME to Unix timestamp (seconds since 1970).
pub fn filetime_to_unix(ft: u64) -> Option<i64> {
    if ft == 0 || ft < FILETIME_UNIX_EPOCH_OFFSET {
        return None;
    }
    let unix_100ns = ft - FILETIME_UNIX_EPOCH_OFFSET;
    let unix_secs = (unix_100ns / 10_000_000) as i64;
    // Sanity: reject timestamps after year 2100
    if unix_secs > 4_102_444_800 {
        return None;
    }
    Some(unix_secs)
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Decode UTF-16LE bytes to a String.
fn decode_utf16le(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let u16_vec: Vec<u16> = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|&c| c != 0)
        .collect();

    if u16_vec.is_empty() {
        return None;
    }

    String::from_utf16(&u16_vec).ok()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_to_unix() {
        // Known conversion: 2024-01-01 00:00:00 UTC
        // FILETIME = (1704067200 * 10_000_000) + 116444736000000000
        //          = 17040672000000000 + 116444736000000000
        //          = 133485408000000000
        let ft = 133_485_408_000_000_000u64;
        let unix = filetime_to_unix(ft);
        assert!(unix.is_some());
        let ts = unix.unwrap();
        assert_eq!(
            ts, 1_704_067_200,
            "Expected 1704067200 (2024-01-01), got {}",
            ts
        );
    }

    #[test]
    fn test_filetime_zero_returns_none() {
        assert_eq!(filetime_to_unix(0), None);
    }

    #[test]
    fn test_filetime_before_unix_epoch_returns_none() {
        // FILETIME for 1969 — before Unix epoch
        assert_eq!(filetime_to_unix(100_000_000), None);
    }

    #[test]
    fn test_parse_data_runs() {
        // Simple data run: header=0x11 (1 byte length, 1 byte offset)
        // length=4, offset=10
        let data = [0x11, 0x04, 0x0A, 0x00];
        let runs = parse_data_runs(&data);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].cluster_offset, Some(10));
        assert_eq!(runs[0].cluster_length, 4);
    }

    #[test]
    fn test_parse_data_runs_multiple() {
        // Two runs: first at LCN 100 len 8, second relative +50 len 4
        let data = [
            0x21, 0x08, 0x64, 0x00, // header=0x21, len=8, offset=100
            0x21, 0x04, 0x32, 0x00, // header=0x21, len=4, offset=+50
            0x00, // end
        ];
        let runs = parse_data_runs(&data);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].cluster_offset, Some(100));
        assert_eq!(runs[0].cluster_length, 8);
        assert_eq!(runs[1].cluster_offset, Some(150)); // 100 + 50
        assert_eq!(runs[1].cluster_length, 4);
    }

    #[test]
    fn test_parse_data_runs_empty() {
        let data = [0x00];
        let runs = parse_data_runs(&data);
        assert!(runs.is_empty());
    }

    #[test]
    fn test_decode_utf16le() {
        // "hello" in UTF-16LE
        let data = [0x68, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        let s = decode_utf16le(&data);
        assert_eq!(s, Some("hello".to_string()));
    }

    #[test]
    fn test_decode_utf16le_with_null() {
        // "hi" + null terminator in UTF-16LE
        let data = [0x68, 0x00, 0x69, 0x00, 0x00, 0x00, 0x41, 0x00];
        let s = decode_utf16le(&data);
        assert_eq!(s, Some("hi".to_string()));
    }

    #[test]
    fn test_parse_ntfs_boot_sector() {
        // Construct a minimal valid NTFS boot sector
        let mut vbr = [0u8; 512];
        // Jump instruction
        vbr[0] = 0xEB;
        vbr[1] = 0x52;
        vbr[2] = 0x90;
        // OEM ID "NTFS    "
        vbr[3..11].copy_from_slice(b"NTFS    ");
        // Bytes per sector = 512
        vbr[0x0B] = 0x00;
        vbr[0x0C] = 0x02;
        // Sectors per cluster = 8
        vbr[0x0D] = 0x08;
        // Total sectors = 1000000
        let total: u64 = 1_000_000;
        vbr[0x28..0x30].copy_from_slice(&total.to_le_bytes());
        // MFT LCN = 786432
        let mft_lcn: i64 = 786432;
        vbr[0x30..0x38].copy_from_slice(&mft_lcn.to_le_bytes());
        // Clusters per MFT record = -10 (means 2^10 = 1024 bytes)
        vbr[0x40] = (-10i8) as u8;

        let mut cursor = std::io::Cursor::new(&vbr[..]);
        let boot = MftWalker::read_boot_sector(&mut cursor, 0).expect("boot sector parse");

        assert_eq!(boot.bytes_per_sector, 512);
        assert_eq!(boot.sectors_per_cluster, 8);
        assert_eq!(boot.cluster_size, 4096);
        assert_eq!(boot.record_size, 1024);
        assert_eq!(boot.total_sectors, 1_000_000);
        // MFT offset = 786432 * 4096 = 3221225472
        assert_eq!(boot.mft_offset, 786432 * 4096);
    }
}

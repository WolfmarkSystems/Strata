//! vt-core: filesystem and image abstraction for Strata Tree.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub type ParseResult<T> = Result<T>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectType {
    File,
    Directory,
    Unallocated,
    Slack,
    ArchiveMember,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FsType {
    Ntfs,
    Fat,
    Ext4,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    pub path: String,
    pub object_type: ObjectType,
    pub fs_type: FsType,
    pub size: u64,
    pub inode: Option<u64>,
    pub created_at: Option<u64>,
    pub modified_at: Option<u64>,
}

#[derive(Default)]
pub struct ScanOptions {
    pub progress: Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
    pub cancel: Option<Arc<AtomicBool>>,
}

pub trait ImageReader: Send + Sync {
    fn open(path: &str) -> Result<Box<dyn ImageReader>>
    where
        Self: Sized;
    fn len(&self) -> Result<u64>;
    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
    fn read_at(&mut self, offset: u64, size: usize) -> Result<Vec<u8>>;
}

pub struct RawImageReader {
    file: File,
    size: u64,
}

impl ImageReader for RawImageReader {
    fn open(path: &str) -> Result<Box<dyn ImageReader>> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(Box::new(RawImageReader { file, size }))
    }

    fn len(&self) -> Result<u64> {
        Ok(self.size)
    }

    fn read_at(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size];
        self.file.seek(SeekFrom::Start(offset))?;
        let read = self.file.read(&mut buf)?;
        buf.truncate(read);
        Ok(buf)
    }
}

pub trait FsParser: Send + Sync {
    fn scan(&self) -> ParseResult<Vec<Object>>;
    fn path_exists(&self, path: &str) -> ParseResult<bool>;
}

pub struct DummyFsParser {
    root: String,
}

impl DummyFsParser {
    pub fn new(root: &str) -> Self {
        Self {
            root: root.to_string(),
        }
    }
}

impl FsParser for DummyFsParser {
    fn scan(&self) -> ParseResult<Vec<Object>> {
        let mut items = vec![];
        if Path::new(&self.root).exists() {
            items.push(Object {
                path: self.root.clone(),
                object_type: ObjectType::Directory,
                fs_type: FsType::Unknown,
                size: 0,
                inode: None,
                created_at: None,
                modified_at: None,
            });
        }
        Ok(items)
    }

    fn path_exists(&self, path: &str) -> ParseResult<bool> {
        Ok(Path::new(path).exists())
    }
}

pub struct NtfsParser {
    root: PathBuf,
}

impl NtfsParser {
    pub fn new(root: &str) -> Self {
        Self {
            root: PathBuf::from(root),
        }
    }

    fn collect_entries(path: &Path, items: &mut Vec<Object>) -> ParseResult<()> {
        if path.is_dir() {
            items.push(Object {
                path: path.display().to_string(),
                object_type: ObjectType::Directory,
                fs_type: FsType::Ntfs,
                size: 0,
                inode: None,
                created_at: None,
                modified_at: None,
            });
            for entry in strata_fs::read_dir(path)? {
                let entry: std::fs::DirEntry = entry?;
                let p = entry.path();
                NtfsParser::collect_entries(&p, items)?;
            }
        } else if path.is_file() {
            let meta = strata_fs::metadata(path)?;
            items.push(Object {
                path: path.display().to_string(),
                object_type: ObjectType::File,
                fs_type: FsType::Ntfs,
                size: meta.len(),
                inode: None,
                created_at: None,
                modified_at: None,
            });
        }
        Ok(())
    }
}

impl FsParser for NtfsParser {
    fn scan(&self) -> ParseResult<Vec<Object>> {
        let mut results = vec![];
        if self.root.exists() {
            NtfsParser::collect_entries(&self.root, &mut results)?;
        }
        Ok(results)
    }

    fn path_exists(&self, path: &str) -> ParseResult<bool> {
        Ok(Path::new(path).exists())
    }
}

fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16> {
    if buf.len() < offset + 2 {
        return Err(anyhow!("buffer too small for u16"));
    }
    Ok(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

fn read_u8(buf: &[u8], offset: usize) -> Result<u8> {
    if buf.len() <= offset {
        return Err(anyhow!("buffer too small for u8"));
    }
    Ok(buf[offset])
}

fn read_i8(buf: &[u8], offset: usize) -> Result<i8> {
    Ok(read_u8(buf, offset)? as i8)
}

fn read_i64_le(buf: &[u8], offset: usize) -> Result<i64> {
    if buf.len() < offset + 8 {
        return Err(anyhow!("buffer too small for i64"));
    }
    Ok(i64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]))
}

fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64> {
    if buf.len() < offset + 8 {
        return Err(anyhow!("buffer too small for u64"));
    }
    Ok(u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]))
}

fn parse_data_runs(runlist: &[u8]) -> Result<Vec<(u64, i64)>> {
    let mut runs = Vec::new();
    let mut i = 0;
    let mut prev_lcn: i64 = 0;

    while i < runlist.len() {
        let header = runlist[i];
        i += 1;
        if header == 0 {
            break;
        }

        let len_size = (header & 0x0F) as usize;
        let off_size = (header >> 4) as usize;

        if i + len_size + off_size > runlist.len() {
            return Err(anyhow!("invalid runlist length"));
        }

        let mut cluster_count: u64 = 0;
        for b in 0..len_size {
            cluster_count |= (runlist[i + b] as u64) << (8 * b);
        }
        i += len_size;

        let mut offset_lcn: i64 = 0;
        if off_size > 0 {
            for b in 0..off_size {
                offset_lcn |= (runlist[i + b] as i64) << (8 * b);
            }
            // sign-extend if negative
            if (runlist[i + off_size - 1] & 0x80) != 0 {
                let shift = 64 - (off_size * 8);
                offset_lcn = (offset_lcn << shift) >> shift;
            }
        }
        i += off_size;

        prev_lcn = prev_lcn.wrapping_add(offset_lcn);
        runs.push((cluster_count, prev_lcn));
    }

    Ok(runs)
}

fn read_nonresident_data(
    reader: &mut dyn ImageReader,
    runs: &[(u64, i64)],
    cluster_size: u64,
    data_size: u64,
) -> Result<Vec<u8>> {
    let mut buffer: Vec<u8> = Vec::with_capacity(data_size as usize);
    let mut remaining = data_size;

    for (count, lcn) in runs {
        if *count == 0 {
            continue;
        }

        let bytes_to_read = count.saturating_mul(cluster_size);
        if *lcn < 0 {
            return Err(anyhow!("invalid negative LCN in runlist"));
        }

        if *lcn == 0 {
            // sparse run
            let to_fill = bytes_to_read.min(remaining);
            buffer.extend(vec![0u8; to_fill as usize]);
            remaining = remaining.saturating_sub(to_fill);
        } else {
            let offset = (*lcn as u64).saturating_mul(cluster_size);
            let read_bytes = reader.read_at(offset, bytes_to_read as usize)?;
            let take = read_bytes.len().min(remaining as usize);
            buffer.extend_from_slice(&read_bytes[..take]);
            remaining = remaining.saturating_sub(take as u64);
        }

        if remaining == 0 {
            break;
        }
    }

    Ok(buffer)
}

fn apply_fixup(rec: &mut [u8]) -> Result<()> {
    let usa_offset = read_u16_le(rec, 4)? as usize;
    let usa_count = read_u16_le(rec, 6)? as usize;

    // nonstandard MFT records may omit update sequence handling; skip fixup if not usable
    if usa_count < 2 || usa_offset == 0 || usa_offset + usa_count * 2 > rec.len() {
        return Ok(());
    }

    let usa_value = read_u16_le(rec, usa_offset)?;
    let sector_size = 512;
    let sector_count = usa_count - 1;

    for i in 0..sector_count {
        let expected = read_u16_le(rec, usa_offset + 2 + i * 2)?;
        let sector_end = (i + 1) * sector_size;
        if sector_end < 2 || sector_end > rec.len() {
            return Err(anyhow!("fixup sector boundary out of range"));
        }
        let current = u16::from_le_bytes([rec[sector_end - 2], rec[sector_end - 1]]);
        if current != expected {
            return Err(anyhow!("fixup mismatch detected"));
        }
        rec[sector_end - 2..sector_end].copy_from_slice(&usa_value.to_le_bytes());
    }
    Ok(())
}

fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32> {
    if buf.len() < offset + 4 {
        return Err(anyhow!("buffer too small for u32"));
    }
    Ok(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

fn decode_utf16_string(data: &[u8], len: usize) -> Result<String> {
    if data.len() < len * 2 {
        return Err(anyhow!("buffer too small for utf16 string"));
    }
    let mut u16_buf = Vec::with_capacity(len);
    for i in 0..len {
        let lo = data[2 * i];
        let hi = data[2 * i + 1];
        u16_buf.push(u16::from_le_bytes([lo, hi]));
    }
    String::from_utf16(&u16_buf).map_err(|e| anyhow!("utf16 decode error: {}", e))
}

#[derive(Debug)]
struct MftNodeTemp {
    record_num: u64,
    name: String,
    parent: u64,
    size: u64,
    is_dir: bool,
    data_runs: Option<Vec<(u64, i64)>>,
}

fn parse_mft_record(rec: &[u8]) -> Option<MftNodeTemp> {
    if !rec.starts_with(b"FILE") {
        return None;
    }

    let mut name = None;
    let mut parent = 0u64;
    let mut size = 0u64;
    let mut is_dir = false;
    let mut data_runs: Option<Vec<(u64, i64)>> = None;

    let attr_offset = read_u16_le(rec, 20).ok()? as usize;
    let mut cursor = attr_offset;

    while cursor + 16 <= rec.len() {
        let attr_type = read_u32_le(rec, cursor).ok()?;
        if attr_type == 0xFFFFFFFF {
            break;
        }

        let attr_len = read_u32_le(rec, cursor + 4).ok()? as usize;
        if attr_len == 0 || cursor + attr_len > rec.len() {
            break;
        }

        let non_resident = read_u8(rec, cursor + 8).ok()?;
        let flags = read_u16_le(rec, cursor + 12).ok()?;

        // Standard information: directory flag
        if attr_type == 0x10 {
            let content_offset = read_u16_le(rec, cursor + 20).ok()? as usize;
            let body_start = cursor + content_offset;
            if body_start + 0x40 <= rec.len() {
                let file_flags = read_u32_le(rec, body_start + 32).unwrap_or(0);
                is_dir = is_dir || (file_flags & 0x10000000) != 0;
            }
        }

        // File name attribute
        if attr_type == 0x30 && non_resident == 0 {
            let content_offset = read_u16_le(rec, cursor + 20).ok()? as usize;
            let body_start = cursor + content_offset;
            if body_start + 66 <= rec.len() {
                let parent_ref_full = read_i64_le(rec, body_start).ok()? as u64;
                let candidate_parent = parent_ref_full & 0xFFFFFFFFFFFF;
                if candidate_parent != 0 {
                    parent = candidate_parent;
                }

                let filename_len = read_u8(rec, body_start + 64).ok()? as usize;
                let filename_offset = body_start + 66;
                if filename_offset + filename_len * 2 <= rec.len() {
                    let filename_bytes = &rec[filename_offset..filename_offset + filename_len * 2];
                    if let Ok(filename) = decode_utf16_string(filename_bytes, filename_len) {
                        name = Some(filename);
                    }
                }

                let file_attr_flags = read_u32_le(rec, body_start + 56).unwrap_or(0);
                is_dir = is_dir || (file_attr_flags & 0x10000000) != 0;
            }
        }

        // Directory index attributes: treat as directory
        if attr_type == 0x90 || attr_type == 0xA0 {
            is_dir = true;
        }

        let _flags = flags; // suppress unused-variable warning

        // Data attribute
        if attr_type == 0x80 {
            if non_resident == 1 {
                let runlist_offset = read_u16_le(rec, cursor + 32).ok()? as usize;
                let data_size_val = read_u64_le(rec, cursor + 48).ok()?;
                size = data_size_val;
                let runs_start = cursor + runlist_offset;
                if runs_start < cursor + attr_len && runs_start < rec.len() {
                    let runlist = &rec[runs_start..cursor + attr_len];
                    if let Ok(runs) = parse_data_runs(runlist) {
                        data_runs = Some(runs);
                    }
                }
            } else {
                let content_size = read_u32_le(rec, cursor + 16).ok()? as u64;
                size = content_size;
            }
        }

        cursor += attr_len;
    }

    let name = name.unwrap_or_else(|| String::from("<unnamed>"));

    Some(MftNodeTemp {
        record_num: 0,
        name,
        parent,
        size,
        is_dir,
        data_runs,
    })
}

pub fn parse_ntfs_mft(image_path: &str) -> ParseResult<Vec<Object>> {
    let mut reader = RawImageReader::open(image_path)?;
    let boot_sector = reader.read_at(0, 512)?;
    if &boot_sector[3..11] != b"NTFS    " {
        return Err(anyhow!("not NTFS image"));
    }

    let bytes_per_sector = read_u16_le(&boot_sector, 11)? as u64;
    let sectors_per_cluster = read_u8(&boot_sector, 13)? as u64;
    let cluster_size = bytes_per_sector * sectors_per_cluster;
    let mft_cluster = read_i64_le(&boot_sector, 48)?;

    if mft_cluster < 0 {
        return Err(anyhow!("invalid MFT cluster"));
    }

    let mft_offset = (mft_cluster as u64).saturating_mul(cluster_size);
    let mft_entry_size = {
        let size_byte = read_i8(&boot_sector, 64)?;
        if size_byte > 0 {
            (size_byte as u64) * cluster_size
        } else {
            2u64.pow((-size_byte) as u32)
        }
    };

    // limit to first 256 entries to keep quick
    let mut entries = vec![];
    let max_entries = 256;
    let read_len = (mft_entry_size * max_entries).min(10 * 1024 * 1024); // avoid huge allocation
    let mft_data = reader.read_at(mft_offset, read_len as usize)?;

    #[allow(dead_code)]
    struct MftNode {
        record_num: u64,
        name: String,
        parent: u64,
        size: u64,
        is_dir: bool,
        data_runs: Option<Vec<(u64, i64)>>,
    }

    let mut nodes = Vec::new();

    for i in 0..max_entries {
        let start = (i * mft_entry_size) as usize;
        let end = start + mft_entry_size as usize;
        if end > mft_data.len() {
            break;
        }
        let rec = &mft_data[start..end];
        if !rec.starts_with(b"FILE") {
            continue;
        }

        let mut rec_buf = rec.to_vec();
        if apply_fixup(&mut rec_buf).is_err() {
            continue;
        }

        if let Some(mut node) = parse_mft_record(&rec_buf) {
            node.record_num = i;
            if node.name.starts_with("$") {
                // skip metadata records that are not user files
                continue;
            }
            nodes.push(MftNode {
                record_num: i,
                name: node.name,
                parent: node.parent,
                size: node.size,
                is_dir: node.is_dir,
                data_runs: node.data_runs,
            });
        }
    }

    let node_map: HashMap<u64, &MftNode> = nodes.iter().map(|n| (n.record_num, n)).collect();

    for node in &nodes {
        let mut path = node.name.clone();
        let mut current = node.parent;
        let mut depth = 0;

        while depth < 64 {
            if let Some(parent_node) = node_map.get(&current) {
                if parent_node.record_num == node.record_num {
                    break;
                }
                path = format!("{}/{}", parent_node.name, path);
                if parent_node.parent == parent_node.record_num {
                    break;
                }
                current = parent_node.parent;
            } else {
                if current != 0 {
                    path = format!("{}/{}", current, path);
                }
                break;
            }
            depth += 1;
        }

        entries.push(Object {
            path,
            object_type: if node.is_dir {
                ObjectType::Directory
            } else {
                ObjectType::File
            },
            fs_type: FsType::Ntfs,
            size: node.size.max(mft_entry_size),
            inode: Some(node.record_num),
            created_at: None,
            modified_at: None,
        });
    }

    Ok(entries)
}

pub fn read_mft_file_data(image_path: &str, record_num: u64) -> ParseResult<Vec<u8>> {
    let mut reader = RawImageReader::open(image_path)?;
    let boot_sector = reader.read_at(0, 512)?;
    if &boot_sector[3..11] != b"NTFS    " {
        return Err(anyhow!("not NTFS image"));
    }

    let bytes_per_sector = read_u16_le(&boot_sector, 11)? as u64;
    let sectors_per_cluster = read_u8(&boot_sector, 13)? as u64;
    let cluster_size = bytes_per_sector * sectors_per_cluster;
    let mft_cluster = read_i64_le(&boot_sector, 48)?;
    let mft_entry_size = {
        let size_byte = read_i8(&boot_sector, 64)?;
        if size_byte > 0 {
            (size_byte as u64) * cluster_size
        } else {
            2u64.pow((-size_byte) as u32)
        }
    };

    let mft_offset = (mft_cluster as u64).saturating_mul(cluster_size);
    let record_offset = mft_offset + record_num.saturating_mul(mft_entry_size);
    let rec = reader.read_at(record_offset, mft_entry_size as usize)?;

    let node = parse_mft_record(&rec).ok_or_else(|| anyhow!("no record for entry"))?;

    if let Some(runs) = node.data_runs {
        let data = read_nonresident_data(&mut *reader, &runs, cluster_size, node.size)?;
        return Ok(data);
    }

    Ok(Vec::new())
}

pub fn scan_fs_image_with_options(
    image_path: &str,
    opts: Option<ScanOptions>,
) -> ParseResult<Vec<Object>> {
    let options = opts.unwrap_or_default();

    if let Some(cancel_flag) = &options.cancel {
        if cancel_flag.load(Ordering::Relaxed) {
            return Err(anyhow!("scan canceled"));
        }
    }

    if Path::new(image_path).is_dir() {
        let parser = NtfsParser::new(image_path);
        let result = parser.scan()?;
        if let Some(cb) = &options.progress {
            cb(result.len() as u64, result.len() as u64);
        }
        Ok(result)
    } else {
        // attempt NTFS image MFT parsing first
        match parse_ntfs_mft(image_path) {
            Ok(it) => {
                if let Some(cb) = &options.progress {
                    cb(it.len() as u64, it.len() as u64);
                }
                Ok(it)
            }
            Err(_) => {
                let parser = NtfsParser::new(image_path);
                let result = parser.scan()?;
                if let Some(cb) = &options.progress {
                    cb(result.len() as u64, result.len() as u64);
                }
                Ok(result)
            }
        }
    }
}

pub fn scan_fs_image(image_path: &str) -> ParseResult<Vec<Object>> {
    scan_fs_image_with_options(image_path, None)
}

pub fn scan_fs_image_chunked(
    image_path: &str,
    chunk_size: usize,
    opts: Option<ScanOptions>,
) -> ParseResult<Vec<Object>> {
    let mut reader = RawImageReader::open(image_path)?;
    let total = reader.len()?;
    let mut offset = 0u64;
    while offset < total {
        let chunk = ((total - offset) as usize).min(chunk_size);
        let _ = reader.read_at(offset, chunk)?;
        offset += chunk as u64;
        if let Some(opt) = &opts {
            if let Some(cb) = &opt.progress {
                cb(offset, total);
            }
            if let Some(cancel) = &opt.cancel {
                if cancel.load(Ordering::Relaxed) {
                    return Err(anyhow!("scan canceled"));
                }
            }
        }
    }
    scan_fs_image_with_options(image_path, opts)
}

#[derive(Debug, Clone)]
pub enum HashType {
    Sha256,
}

pub fn hash_file(path: &Path, algorithm: HashType) -> Result<String> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    let digest = match algorithm {
        HashType::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&buf);
            hasher.finalize().to_vec()
        }
    };

    Ok(hex::encode(digest))
}

pub fn self_test() -> ParseResult<()> {
    let parser = DummyFsParser::new(".");
    let items = parser.scan()?;
    assert!(!items.is_empty());

    let parser = NtfsParser::new(".");
    let ntfs_items = parser.scan()?;
    assert!(ntfs_items.len() >= items.len());

    let hash = hash_file(Path::new("Cargo.toml"), HashType::Sha256)?;
    assert!(!hash.is_empty());

    Ok(())
}

pub struct InMemoryDocumentIndex {
    index: HashMap<String, Vec<String>>,
}

impl Default for InMemoryDocumentIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryDocumentIndex {
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
        }
    }

    pub fn add_document(&mut self, id: &str, content: &str) {
        for token in tokenize(content) {
            let bucket = self.index.entry(token).or_default();
            if !bucket.contains(&id.to_string()) {
                bucket.push(id.to_string());
            }
        }
    }

    pub fn query(&self, term: &str) -> Vec<String> {
        self.index
            .get(&term.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }
}

fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{remove_file, write};

    #[test]
    fn test_hash_file_sha256() {
        let tmp = "vt_core_test_tmp.txt";
        let data = b"test123";
        write(tmp, data).unwrap();
        let hash = hash_file(Path::new(tmp), HashType::Sha256).unwrap();
        assert_eq!(hash.len(), 64);
        remove_file(tmp).unwrap();
    }

    #[test]
    fn test_ntfs_parser_scan() {
        let parser = NtfsParser::new(".");
        let items = parser.scan().unwrap();
        assert!(!items.is_empty());
        assert!(items.iter().any(|i| i.path.ends_with("Cargo.toml")));
    }

    #[test]
    fn test_scan_fs_image_is_dir() {
        let items = scan_fs_image(".").unwrap();
        assert!(!items.is_empty());
    }

    #[test]
    fn test_parse_ntfs_mft_synthetic() {
        let tmp = "vt_core_test_ntfs_image.bin";
        let mut data = vec![0u8; 16384];
        data[3..11].copy_from_slice(b"NTFS    ");
        data[11..13].copy_from_slice(&512u16.to_le_bytes());
        data[13] = 1;
        data[48..56].copy_from_slice(&4i64.to_le_bytes());
        data[64] = (-10i8) as u8; // 1024 byte MFT entry

        let mft_offset: usize = 4 * 512;
        let entry_size = 1024;

        // parent record 0 name 'parent'
        let entry0 = mft_offset;
        data[entry0..entry0 + 4].copy_from_slice(b"FILE");
        let attr_off = 0x30;
        data[entry0 + 20..entry0 + 22].copy_from_slice(&(attr_off as u16).to_le_bytes());
        data[entry0 + attr_off..entry0 + attr_off + 4].copy_from_slice(&0x30u32.to_le_bytes());
        data[entry0 + attr_off + 4..entry0 + attr_off + 8].copy_from_slice(&80u32.to_le_bytes());
        data[entry0 + attr_off + 8] = 0;
        data[entry0 + attr_off + 20..entry0 + attr_off + 22]
            .copy_from_slice(&0x18u16.to_le_bytes());
        data[entry0 + attr_off + 0x18..entry0 + attr_off + 0x20]
            .copy_from_slice(&0u64.to_le_bytes()); // parent ref to self root
        let parent_name = "parent";
        data[entry0 + attr_off + 0x18 + 64] = parent_name.len() as u8;
        for (i, c) in parent_name.encode_utf16().enumerate() {
            let offset = entry0 + attr_off + 0x18 + 66 + i * 2;
            data[offset..offset + 2].copy_from_slice(&c.to_le_bytes());
        }

        // child record 1 name 'child', parent ref 0
        let entry1 = entry0 + entry_size;
        data[entry1..entry1 + 4].copy_from_slice(b"FILE");
        data[entry1 + 20..entry1 + 22].copy_from_slice(&(attr_off as u16).to_le_bytes());
        data[entry1 + attr_off..entry1 + attr_off + 4].copy_from_slice(&0x30u32.to_le_bytes());
        data[entry1 + attr_off + 4..entry1 + attr_off + 8].copy_from_slice(&80u32.to_le_bytes());
        data[entry1 + attr_off + 8] = 0;
        data[entry1 + attr_off + 20..entry1 + attr_off + 22]
            .copy_from_slice(&0x18u16.to_le_bytes());
        // write parent reference to 0 in file_name
        data[entry1 + attr_off + 0x18..entry1 + attr_off + 0x20]
            .copy_from_slice(&0u64.to_le_bytes());
        let child_name = "child";
        data[entry1 + attr_off + 0x18 + 64] = child_name.len() as u8;
        for (i, c) in child_name.encode_utf16().enumerate() {
            let offset = entry1 + attr_off + 0x18 + 66 + i * 2;
            data[offset..offset + 2].copy_from_slice(&c.to_le_bytes());
        }

        std::fs::write(tmp, &data).unwrap();

        let mut reader = RawImageReader::open(tmp).unwrap();
        println!("entry0={}, entry1={}", entry0, entry1);
        let rec0 = reader.read_at(entry0 as u64, entry_size).unwrap();
        let rec1 = reader.read_at(entry1 as u64, entry_size).unwrap();
        println!("rec1 head={:?}", &rec1[0..8]);
        assert_eq!(&rec0[0..4], b"FILE");
        assert_eq!(&rec1[0..4], b"FILE");
        let node0 = parse_mft_record(&rec0).unwrap();
        let node1 = parse_mft_record(&rec1).unwrap();
        println!("node0: {:?}, node1: {:?}", node0, node1);

        let entries = parse_ntfs_mft(tmp).unwrap();
        println!(
            "entries: {:?}",
            entries.iter().map(|o| &o.path).collect::<Vec<_>>()
        );
        assert!(entries.iter().any(|e| e.path == "parent"));
        assert!(entries.iter().any(|e| e.path == "parent/child"));

        std::fs::remove_file(tmp).unwrap();
    }

    #[test]
    fn test_scan_fs_image_with_options_cancel() {
        let cancel = Arc::new(AtomicBool::new(true));
        let opts = ScanOptions {
            progress: Some(Arc::new(move |_processed, _total| {})),
            cancel: Some(cancel),
        };

        let result = scan_fs_image_with_options(".", Some(opts));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_data_runs() {
        // 0x21,0x05 means length=1, offset=5; 0x00 end
        let runlist = vec![0x21u8, 0x01, 0x05, 0x00];
        let runs = parse_data_runs(&runlist).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0], (1, 5));
    }

    #[test]
    fn test_read_mft_file_data_nonresident() {
        // synthetic MFT with nonresident DATA for record 1: 1 cluster at lcn 10
        let tmp = "vt_core_test_ntfs_image_nonresident.bin";
        let mut data = vec![0u8; 8192];
        data[3..11].copy_from_slice(b"NTFS    ");
        data[11..13].copy_from_slice(&512u16.to_le_bytes());
        data[13] = 1;
        data[48..56].copy_from_slice(&4i64.to_le_bytes());
        data[64] = (-10i8) as u8; // 1024-byte mft record

        let cluster_size = 512u64;
        let mft_offset = 4 * 512;
        let entry_size = 1024;

        // record 1 has nonresident data runlist
        let record1 = mft_offset + entry_size;
        data[record1..record1 + 4].copy_from_slice(b"FILE");
        data[record1 + 20..record1 + 22].copy_from_slice(&(0x30u16).to_le_bytes()); // attribute offset 48? Actually 0x30
                                                                                    // In this synthetic we just need parse_mft_record to get runlist; put attr at 48
        let attr_off = 0x30;
        data[record1 + 20..record1 + 22].copy_from_slice(&(attr_off as u16).to_le_bytes());
        data[record1 + attr_off..record1 + attr_off + 4].copy_from_slice(&0x80u32.to_le_bytes()); // data attribute
        data[record1 + attr_off + 4..record1 + attr_off + 8].copy_from_slice(&112u32.to_le_bytes());
        data[record1 + attr_off + 8] = 1; // nonresident
        data[record1 + attr_off + 16..record1 + attr_off + 20].copy_from_slice(&0u32.to_le_bytes()); // content size not used
        data[record1 + attr_off + 32..record1 + attr_off + 34]
            .copy_from_slice(&(0x40u16).to_le_bytes()); // runlist offset
        data[record1 + attr_off + 40..record1 + attr_off + 48].copy_from_slice(&8u64.to_le_bytes()); // allocated size
        data[record1 + attr_off + 48..record1 + attr_off + 56]
            .copy_from_slice(&800u64.to_le_bytes()); // data size
                                                     // runlist at offset 0x40 within attribute
        let runlist_start = record1 + attr_off + 0x40;
        data[runlist_start] = 0x21;
        data[runlist_start + 1] = 1;
        data[runlist_start + 2] = 10;
        data[runlist_start + 3] = 0x00;

        // write content at cluster 10 (cluster_size=512)
        let content_offset = 10 * cluster_size;
        if content_offset + 4 < data.len() as u64 {
            let off = content_offset as usize;
            data[off..off + 4].copy_from_slice(b"DATA");
        }

        std::fs::write(tmp, &data).unwrap();

        // Verify specific record parse path and runlist decoding before calling high-level method
        let mut reader = RawImageReader::open(tmp).unwrap();
        let rec = reader.read_at(record1 as u64, entry_size).unwrap();
        let node = parse_mft_record(&rec).expect("parse record");
        assert!(node.data_runs.is_some());
        assert_eq!(node.data_runs.as_ref().unwrap()[0], (1, 10));

        let result = read_mft_file_data(tmp, 1).unwrap();
        assert!(result.starts_with(b"DATA"));

        std::fs::remove_file(tmp).unwrap();
    }

    #[test]
    fn test_in_memory_index() {
        let mut idx = InMemoryDocumentIndex::new();
        idx.add_document("1", "password file secret");
        idx.add_document("2", "user secret key");
        let results = idx.query("secret");
        assert_eq!(results.len(), 2);
    }
}

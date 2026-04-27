//! UNPACK-2 — streaming / on-demand archive access.
//!
//! Full extraction is the right default when the examiner has disk
//! space, but a 500 GB Cellebrite EXTRACTION_FFS.zip on a 256 GB SSD
//! asks for streaming: index metadata up front, extract individual
//! files lazily when a plugin actually reaches for them, cache a
//! bounded working set.
//!
//! This module implements that surface for zip archives — the
//! file-format that dominates the nested-container cases we saw in
//! the v5 field run (UFED / Takeout / Android backup). Tar streams
//! don't random-access without a full index, so they stay with
//! UNPACK-1's ExtractToDisk path; tar support can be added to this
//! surface once the v6 matrix demands it.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Extraction strategy. Picked automatically by `auto_select_mode` or
/// forced by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionMode {
    /// Everything lands on disk (UNPACK-1 behaviour).
    ExtractToDisk,
    /// Only files plugins actually read get extracted; the rest stays
    /// in the archive.
    StreamOnDemand,
    /// Metadata eagerly, content lazily.
    HybridStream,
}

/// Pick an extraction mode by comparing archive size to free disk.
///
/// * if there's 3× headroom → full extract
/// * if there's any headroom at all → hybrid
/// * otherwise → streaming mandatory
pub fn auto_select_mode(archive_size: u64, available_disk: u64) -> ExtractionMode {
    if archive_size.saturating_mul(3) <= available_disk {
        ExtractionMode::ExtractToDisk
    } else if archive_size <= available_disk {
        ExtractionMode::HybridStream
    } else {
        ExtractionMode::StreamOnDemand
    }
}

/// One archive entry's metadata as seen from the virtual filesystem.
/// `offset_in_archive` is not useful for every format (zip's internal
/// index handles random access for us), but it's kept in the schema so
/// future tar-seek or ewf-index implementations can populate it.
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub path: PathBuf,
    pub size: u64,
    pub modified: Option<chrono::DateTime<chrono::Utc>>,
    pub permissions: u32,
    pub offset_in_archive: u64,
    pub compression_method: CompressionMethod,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    Stored,
    Deflate,
    Other,
}

/// Bounded LRU of extracted file payloads. The cache is a plain
/// `HashMap` + a `VecDeque` of insertion order so we don't drag
/// another crate in just for an LRU; forensic workloads have highly
/// localised hotspots and even this simple policy wins.
struct PayloadCache {
    map: HashMap<PathBuf, Vec<u8>>,
    order: VecDeque<PathBuf>,
    current_bytes: u64,
    max_bytes: u64,
}

impl PayloadCache {
    fn new(max_bytes: u64) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            current_bytes: 0,
            max_bytes,
        }
    }
    fn get(&mut self, key: &Path) -> Option<Vec<u8>> {
        self.map.get(key).cloned()
    }
    fn put(&mut self, key: PathBuf, bytes: Vec<u8>) {
        let len = bytes.len() as u64;
        // Reject pathological single-file overshoots.
        if len > self.max_bytes {
            return;
        }
        while self.current_bytes + len > self.max_bytes {
            let Some(victim) = self.order.pop_front() else {
                break;
            };
            if let Some(dropped) = self.map.remove(&victim) {
                self.current_bytes = self.current_bytes.saturating_sub(dropped.len() as u64);
            }
        }
        self.current_bytes = self.current_bytes.saturating_add(len);
        self.order.push_back(key.clone());
        self.map.insert(key, bytes);
    }
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// Virtual filesystem over a zip archive. Safe to share across
/// threads — the index is immutable once built, the cache is guarded
/// by a `Mutex`. Plugins can call `read_file`, `exists`, `metadata`,
/// and `list_dir` without caring whether content is on disk or
/// still in the archive.
pub struct VirtualFilesystem {
    archive_path: PathBuf,
    entries: HashMap<PathBuf, ArchiveEntry>,
    cache: Mutex<PayloadCache>,
}

#[derive(Debug, thiserror::Error)]
pub enum VfsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("not found: {0}")]
    NotFound(PathBuf),
    #[error("encrypted entry: {0}")]
    Encrypted(PathBuf),
    #[error("other: {0}")]
    Other(String),
}

impl VirtualFilesystem {
    /// Build a VFS over a zip archive. Reads the central directory
    /// once, caches every entry's metadata, closes the handle; each
    /// `read_file` re-opens for a random-access read.
    pub fn open_zip(archive: &Path, cache_bytes: u64) -> Result<Self, VfsError> {
        let file = fs::File::open(archive)?;
        let mut ar = zip::ZipArchive::new(file)?;
        let mut entries: HashMap<PathBuf, ArchiveEntry> = HashMap::new();
        for i in 0..ar.len() {
            let zf = match ar.by_index(i) {
                Ok(z) => z,
                Err(_) => continue,
            };
            let Some(rel) = zf.enclosed_name().map(|p| p.to_path_buf()) else {
                continue;
            };
            let method = match zf.compression() {
                zip::CompressionMethod::Stored => CompressionMethod::Stored,
                zip::CompressionMethod::Deflated => CompressionMethod::Deflate,
                _ => CompressionMethod::Other,
            };
            entries.insert(
                rel.clone(),
                ArchiveEntry {
                    path: rel,
                    size: zf.size(),
                    modified: None,
                    permissions: zf.unix_mode().unwrap_or(0o644),
                    offset_in_archive: zf.data_start(),
                    compression_method: method,
                    is_dir: zf.is_dir(),
                },
            );
        }
        Ok(Self {
            archive_path: archive.to_path_buf(),
            entries,
            cache: Mutex::new(PayloadCache::new(cache_bytes)),
        })
    }

    pub fn archive_path(&self) -> &Path {
        &self.archive_path
    }

    pub fn metadata(&self, path: &Path) -> Option<&ArchiveEntry> {
        self.entries.get(path)
    }

    pub fn exists(&self, path: &Path) -> bool {
        self.entries.contains_key(path)
    }

    pub fn list_dir(&self, path: &Path) -> Vec<&ArchiveEntry> {
        // Simple prefix match — treat `path` as a directory.
        let prefix = if path.as_os_str().is_empty() {
            PathBuf::new()
        } else {
            path.to_path_buf()
        };
        self.entries
            .values()
            .filter(|e| {
                // Keep only immediate children of `prefix`.
                let Ok(rel) = e.path.strip_prefix(&prefix) else {
                    return false;
                };
                rel.components().count() == 1
            })
            .collect()
    }

    /// Number of entries indexed (files + directories).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the archive has zero entries. Pairs with `len()` to
    /// keep clippy happy.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entry iterator used by the file-index integration layer.
    pub fn entries(&self) -> impl Iterator<Item = &ArchiveEntry> {
        self.entries.values()
    }

    /// Cache hits stay in memory; misses re-open the archive and
    /// extract just that entry's payload.
    pub fn read_file(&self, path: &Path) -> Result<Vec<u8>, VfsError> {
        {
            let mut c = match self.cache.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let Some(bytes) = c.get(path) {
                return Ok(bytes);
            }
        }
        let meta = self
            .entries
            .get(path)
            .ok_or_else(|| VfsError::NotFound(path.to_path_buf()))?;
        if meta.is_dir {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&self.archive_path)?;
        let mut ar = zip::ZipArchive::new(file)?;
        let name_lossy = path.to_string_lossy().into_owned();
        let mut entry = match ar.by_name(&name_lossy) {
            Ok(e) => e,
            Err(zip::result::ZipError::UnsupportedArchive(detail))
                if detail.to_ascii_lowercase().contains("password") =>
            {
                return Err(VfsError::Encrypted(path.to_path_buf()));
            }
            Err(e) => return Err(e.into()),
        };
        if entry.encrypted() {
            return Err(VfsError::Encrypted(path.to_path_buf()));
        }
        let mut out = Vec::with_capacity(meta.size as usize);
        entry.read_to_end(&mut out)?;
        {
            let mut c = match self.cache.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            c.put(path.to_path_buf(), out.clone());
        }
        Ok(out)
    }

    /// How many payloads are currently cached — exposed for tests.
    pub fn cache_entries(&self) -> usize {
        match self.cache.lock() {
            Ok(g) => g.len(),
            Err(p) => p.into_inner().len(),
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).expect("c");
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (n, b) in entries {
            w.start_file::<_, ()>(*n, opts).expect("s");
            w.write_all(b).expect("w");
        }
        w.finish().expect("f");
    }

    #[test]
    fn auto_select_picks_extract_when_plenty_of_space() {
        assert_eq!(
            auto_select_mode(1_000, 10_000),
            ExtractionMode::ExtractToDisk
        );
    }

    #[test]
    fn auto_select_picks_hybrid_when_tight() {
        assert_eq!(auto_select_mode(5_000, 7_000), ExtractionMode::HybridStream);
    }

    #[test]
    fn auto_select_picks_stream_when_archive_bigger_than_disk() {
        assert_eq!(
            auto_select_mode(10_000, 1_000),
            ExtractionMode::StreamOnDemand
        );
    }

    #[test]
    fn vfs_indexes_zip_and_reads_lazily() {
        let dir = tempfile::tempdir().expect("tmp");
        let z = dir.path().join("a.zip");
        make_zip(&z, &[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
        let vfs = VirtualFilesystem::open_zip(&z, 1024).expect("open");
        assert_eq!(vfs.len(), 2);
        assert!(vfs.exists(Path::new("a.txt")));
        let body = vfs.read_file(Path::new("a.txt")).expect("read");
        assert_eq!(body, b"alpha");
    }

    #[test]
    fn vfs_read_matches_extract_to_disk_bytes() {
        let dir = tempfile::tempdir().expect("tmp");
        let z = dir.path().join("a.zip");
        let payload = (0u8..=255u8).cycle().take(4096).collect::<Vec<_>>();
        make_zip(&z, &[("big.bin", payload.as_slice())]);
        let vfs = VirtualFilesystem::open_zip(&z, 8192).expect("open");
        let streamed = vfs.read_file(Path::new("big.bin")).expect("read");
        assert_eq!(streamed, payload);
    }

    #[test]
    fn vfs_cache_eviction_honours_budget() {
        let dir = tempfile::tempdir().expect("tmp");
        let z = dir.path().join("a.zip");
        let big = vec![0xAAu8; 1024];
        make_zip(
            &z,
            &[
                ("a.bin", big.as_slice()),
                ("b.bin", big.as_slice()),
                ("c.bin", big.as_slice()),
            ],
        );
        // 1.5 KiB cap — can hold exactly one 1 KiB payload.
        let vfs = VirtualFilesystem::open_zip(&z, 1500).expect("open");
        let _ = vfs.read_file(Path::new("a.bin")).expect("a");
        assert_eq!(vfs.cache_entries(), 1);
        let _ = vfs.read_file(Path::new("b.bin")).expect("b");
        // After reading b.bin, a.bin should have been evicted.
        assert_eq!(vfs.cache_entries(), 1);
    }

    #[test]
    fn vfs_list_dir_returns_immediate_children() {
        let dir = tempfile::tempdir().expect("tmp");
        let z = dir.path().join("a.zip");
        make_zip(
            &z,
            &[
                ("a/x.txt", b"x"),
                ("a/y.txt", b"y"),
                ("a/sub/z.txt", b"z"),
                ("b.txt", b"b"),
            ],
        );
        let vfs = VirtualFilesystem::open_zip(&z, 1024).expect("open");
        let children: Vec<String> = vfs
            .list_dir(Path::new("a"))
            .iter()
            .map(|e| e.path.to_string_lossy().into_owned())
            .collect();
        // Expect a/x.txt, a/y.txt, a/sub — but not a/sub/z.txt.
        assert!(children.iter().any(|p| p == "a/x.txt"));
        assert!(children.iter().any(|p| p == "a/y.txt"));
        assert!(!children.iter().any(|p| p == "a/sub/z.txt"));
    }

    #[test]
    fn vfs_concurrent_reads_are_safe() {
        let dir = tempfile::tempdir().expect("tmp");
        let z = dir.path().join("a.zip");
        make_zip(&z, &[("x.txt", b"payload")]);
        let vfs = std::sync::Arc::new(VirtualFilesystem::open_zip(&z, 4096).expect("open"));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let v = vfs.clone();
                std::thread::spawn(move || {
                    let b = v.read_file(Path::new("x.txt")).expect("read");
                    assert_eq!(b, b"payload");
                })
            })
            .collect();
        for h in handles {
            h.join().expect("join");
        }
    }
}

//! VFS-1 — the unified `VirtualFilesystem` trait plugins consume.
//!
//! Every filesystem walker (NTFS, APFS, ext4, FAT, HFS+, …) implements
//! this trait. The shell CLI opens an evidence image, walks partitions,
//! builds a VirtualFilesystem per partition (or a `CompositeVfs`
//! combining several), and hands it to plugins through `PluginContext`.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type VfsResult<T> = Result<T, VfsError>;

#[derive(Debug, thiserror::Error)]
pub enum VfsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("not a directory: {0}")]
    NotADirectory(String),
    #[error("not a file: {0}")]
    NotAFile(String),
    #[error("operation unsupported on this filesystem")]
    Unsupported,
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkDecision {
    Descend,
    Skip,
    Stop,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VfsAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    pub archive: bool,
    pub compressed: bool,
    pub encrypted: bool,
    pub sparse: bool,
    pub unix_mode: Option<u32>,
    pub unix_uid: Option<u32>,
    pub unix_gid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VfsSpecific {
    Host,
    Ntfs {
        mft_record: u64,
        resident: bool,
    },
    Apfs {
        object_id: u64,
        snapshot: Option<String>,
    },
    Ext4 {
        inode: u64,
        extents_based: bool,
    },
    Fat {
        cluster: u32,
    },
    HfsPlus {
        catalog_id: u32,
    },
    Raw,
    Composite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsEntry {
    pub path: String,
    pub name: String,
    pub is_directory: bool,
    pub size: u64,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub metadata_changed: Option<DateTime<Utc>>,
    pub attributes: VfsAttributes,
    pub inode_number: Option<u64>,
    pub has_alternate_streams: bool,
    pub fs_specific: VfsSpecific,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsMetadata {
    pub size: u64,
    pub is_directory: bool,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub attributes: VfsAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsDeletedEntry {
    pub path: String,
    pub size: u64,
    pub deleted_at: Option<DateTime<Utc>>,
    pub fs_specific: VfsSpecific,
}

/// The trait every filesystem walker implements.
pub trait VirtualFilesystem: Send + Sync {
    fn fs_type(&self) -> &'static str;

    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>>;

    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>>;

    fn read_file_range(&self, path: &str, offset: u64, len: usize) -> VfsResult<Vec<u8>> {
        let mut bytes = self.read_file(path)?;
        let start = (offset as usize).min(bytes.len());
        let end = (start + len).min(bytes.len());
        Ok(bytes.drain(start..end).collect())
    }

    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata>;

    fn exists(&self, path: &str) -> bool {
        self.metadata(path).is_ok()
    }

    /// Walk the filesystem recursively, calling `filter` for each entry.
    /// Default implementation walks via `list_dir`.
    fn walk(&self, filter: &mut dyn FnMut(&VfsEntry) -> WalkDecision) -> VfsResult<Vec<VfsEntry>> {
        let mut out: Vec<VfsEntry> = Vec::new();
        let mut queue: Vec<String> = vec!["/".into()];
        while let Some(dir) = queue.pop() {
            let entries = match self.list_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries {
                match filter(&entry) {
                    WalkDecision::Stop => return Ok(out),
                    WalkDecision::Skip => {
                        out.push(entry);
                        continue;
                    }
                    WalkDecision::Descend => {}
                }
                if entry.is_directory {
                    queue.push(entry.path.clone());
                }
                out.push(entry);
            }
        }
        Ok(out)
    }

    /// Find files matching a case-insensitive filename (no path
    /// globbing). Walks the whole filesystem and collects matches.
    fn find_by_name(&self, name: &str) -> VfsResult<Vec<VfsEntry>> {
        let needle = name.to_ascii_lowercase();
        let mut out: Vec<VfsEntry> = Vec::new();
        let mut filter = |e: &VfsEntry| -> WalkDecision {
            if !e.is_directory && e.name.to_ascii_lowercase() == needle {
                out.push(e.clone());
            }
            WalkDecision::Descend
        };
        self.walk(&mut filter)?;
        Ok(out)
    }

    fn alternate_streams(&self, _path: &str) -> VfsResult<Vec<String>> {
        Ok(Vec::new())
    }

    fn read_alternate_stream(&self, _path: &str, _stream: &str) -> VfsResult<Vec<u8>> {
        Err(VfsError::Unsupported)
    }

    fn list_deleted(&self) -> VfsResult<Vec<VfsDeletedEntry>> {
        Ok(Vec::new())
    }

    fn read_deleted(&self, _entry: &VfsDeletedEntry) -> VfsResult<Vec<u8>> {
        Err(VfsError::Unsupported)
    }
}

/// CompositeVfs — roots multiple VFS instances under named keys so a
/// single evidence image can carry more than one partition (Windows
/// boot + data, macOS system + data, …) and plugins can walk either
/// a specific partition or the whole union.
pub struct CompositeVfs {
    roots: BTreeMap<String, Arc<dyn VirtualFilesystem>>,
}

impl Default for CompositeVfs {
    fn default() -> Self {
        Self::new()
    }
}

impl CompositeVfs {
    pub fn new() -> Self {
        Self {
            roots: BTreeMap::new(),
        }
    }

    pub fn mount(&mut self, name: &str, vfs: Arc<dyn VirtualFilesystem>) {
        self.roots.insert(format!("/[{name}]"), vfs);
    }

    pub fn roots(&self) -> Vec<&String> {
        #[allow(clippy::iter_kv_map)]
        self.roots.iter().map(|(k, _)| k).collect()
    }

    fn split<'a>(&self, path: &'a str) -> Option<(&String, Arc<dyn VirtualFilesystem>, &'a str)> {
        for (root, vfs) in &self.roots {
            if let Some(rest) = path.strip_prefix(root.as_str()) {
                let rest = if rest.is_empty() { "/" } else { rest };
                return Some((root, vfs.clone(), rest));
            }
        }
        None
    }
}

impl VirtualFilesystem for CompositeVfs {
    fn fs_type(&self) -> &'static str {
        "composite"
    }

    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        if path == "/" {
            #[allow(clippy::iter_kv_map)]
            return Ok(self
                .roots
                .iter()
                .map(|(name, _)| VfsEntry {
                    path: name.clone(),
                    name: name.clone(),
                    is_directory: true,
                    size: 0,
                    created: None,
                    modified: None,
                    accessed: None,
                    metadata_changed: None,
                    attributes: VfsAttributes::default(),
                    inode_number: None,
                    has_alternate_streams: false,
                    fs_specific: VfsSpecific::Composite,
                })
                .collect());
        }
        match self.split(path) {
            Some((_, vfs, rest)) => {
                let mut entries = vfs.list_dir(rest)?;
                // Re-prefix paths so they're addressable through the composite.
                let prefix = path.trim_end_matches('/').to_string();
                for e in &mut entries {
                    e.path = format!("{prefix}/{}", e.name);
                }
                Ok(entries)
            }
            None => Err(VfsError::NotFound(path.into())),
        }
    }

    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        match self.split(path) {
            Some((_, vfs, rest)) => vfs.read_file(rest),
            None => Err(VfsError::NotFound(path.into())),
        }
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
        match self.split(path) {
            Some((_, vfs, rest)) => vfs.metadata(rest),
            None => Err(VfsError::NotFound(path.into())),
        }
    }
}

// ── Host-filesystem adapter (used by plugins that still walk a host
// directory tree — Takeout, unpacked tarballs). Bridges std::fs into
// the VFS trait.

use std::path::PathBuf;

pub struct HostVfs {
    root: PathBuf,
}

impl HostVfs {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn resolve(&self, path: &str) -> PathBuf {
        let rel = path.trim_start_matches('/');
        if rel.is_empty() {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }
}

impl VirtualFilesystem for HostVfs {
    fn fs_type(&self) -> &'static str {
        "host"
    }

    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let p = self.resolve(path);
        if !p.is_dir() {
            return Err(VfsError::NotADirectory(path.into()));
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&p).map_err(VfsError::Io)?.flatten() {
            let meta = entry.metadata().map_err(VfsError::Io)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let entry_path = format!("{}/{}", path.trim_end_matches('/'), name);
            out.push(VfsEntry {
                path: entry_path,
                name,
                is_directory: meta.is_dir(),
                size: meta.len(),
                created: meta.created().ok().map(DateTime::<Utc>::from),
                modified: meta.modified().ok().map(DateTime::<Utc>::from),
                accessed: meta.accessed().ok().map(DateTime::<Utc>::from),
                metadata_changed: None,
                attributes: VfsAttributes::default(),
                inode_number: None,
                has_alternate_streams: false,
                fs_specific: VfsSpecific::Host,
            });
        }
        Ok(out)
    }

    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let p = self.resolve(path);
        std::fs::read(p).map_err(VfsError::Io)
    }

    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> {
        let p = self.resolve(path);
        let m = std::fs::metadata(p).map_err(VfsError::Io)?;
        Ok(VfsMetadata {
            size: m.len(),
            is_directory: m.is_dir(),
            created: m.created().ok().map(DateTime::<Utc>::from),
            modified: m.modified().ok().map(DateTime::<Utc>::from),
            accessed: m.accessed().ok().map(DateTime::<Utc>::from),
            attributes: VfsAttributes::default(),
        })
    }

    fn exists(&self, path: &str) -> bool {
        self.resolve(path).exists()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn host_vfs_lists_directory_and_reads_file() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("sub")).expect("mk");
        fs::write(tmp.path().join("a.txt"), b"hello").expect("w");
        fs::write(tmp.path().join("sub/b.txt"), b"world").expect("w");
        let vfs = HostVfs::new(tmp.path().to_path_buf());
        let root = vfs.list_dir("/").expect("list");
        assert_eq!(root.len(), 2);
        assert!(root.iter().any(|e| e.name == "a.txt" && !e.is_directory));
        let content = vfs.read_file("/a.txt").expect("read");
        assert_eq!(content, b"hello");
    }

    #[test]
    fn host_vfs_find_by_name_walks_recursively() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("a/b/c")).expect("mk");
        fs::write(tmp.path().join("a/b/c/target.txt"), b"x").expect("w");
        let vfs = HostVfs::new(tmp.path().to_path_buf());
        let hits = vfs.find_by_name("target.txt").expect("find");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].path.ends_with("target.txt"));
    }

    #[test]
    fn walk_returns_all_entries() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("dir1")).expect("mk");
        fs::write(tmp.path().join("dir1/a.txt"), b"a").expect("w");
        fs::write(tmp.path().join("b.txt"), b"b").expect("w");
        let vfs = HostVfs::new(tmp.path().to_path_buf());
        let mut filter: Box<dyn FnMut(&VfsEntry) -> WalkDecision> =
            Box::new(|_: &VfsEntry| WalkDecision::Descend);
        let all = vfs.walk(&mut *filter).expect("walk");
        // Should include dir1, dir1/a.txt, b.txt
        assert!(all.iter().any(|e| e.name == "a.txt"));
        assert!(all.iter().any(|e| e.name == "b.txt"));
    }

    #[test]
    fn composite_vfs_routes_under_named_roots() {
        let tmp1 = tempfile::tempdir().expect("t1");
        let tmp2 = tempfile::tempdir().expect("t2");
        fs::write(tmp1.path().join("a.txt"), b"A").expect("w");
        fs::write(tmp2.path().join("b.txt"), b"B").expect("w");
        let mut c = CompositeVfs::new();
        c.mount("C:", Arc::new(HostVfs::new(tmp1.path().to_path_buf())));
        c.mount("D:", Arc::new(HostVfs::new(tmp2.path().to_path_buf())));
        assert_eq!(c.list_dir("/").expect("root").len(), 2);
        assert_eq!(c.read_file("/[C:]/a.txt").expect("read"), b"A");
        assert_eq!(c.read_file("/[D:]/b.txt").expect("read"), b"B");
    }

    #[test]
    fn host_vfs_exists_covers_file_and_dir() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::write(tmp.path().join("x.txt"), b"").expect("w");
        let vfs = HostVfs::new(tmp.path().to_path_buf());
        assert!(vfs.exists("/x.txt"));
        assert!(!vfs.exists("/nope.txt"));
    }

    #[test]
    fn host_vfs_read_range_clamps() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::write(tmp.path().join("x.bin"), [0u8, 1, 2, 3, 4, 5, 6, 7]).expect("w");
        let vfs = HostVfs::new(tmp.path().to_path_buf());
        let slice = vfs.read_file_range("/x.bin", 2, 3).expect("range");
        assert_eq!(slice, vec![2u8, 3, 4]);
    }
}

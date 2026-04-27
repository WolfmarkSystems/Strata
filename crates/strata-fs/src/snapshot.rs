//! Volume snapshot — fast metadata index for large evidence images.
//!
//! `VolumeSnapshot` walks an entire `VirtualFileSystem` once at open time
//! and builds an in-memory index of every file's metadata (path, size,
//! modified time, inode/MFT entry number when available). Subsequent
//! metadata queries are served from the snapshot in O(1) without touching
//! disk, while content reads continue to go through `read_file_range()`
//! on the underlying VFS.
//!
//! This is the same approach X-Ways uses to keep large-image browsing
//! responsive: index once, query forever.
//!
//! ## Usage
//! ```ignore
//! use strata_fs::snapshot::VolumeSnapshot;
//!
//! // First open: walk the VFS and build the snapshot.
//! let snapshot = VolumeSnapshot::build_from_vfs(&*vfs)?;
//!
//! // Every subsequent metadata query is an O(1) HashMap lookup —
//! // zero disk reads.
//! if let Some(entry) = snapshot.metadata(Path::new("/Windows/System32/cmd.exe")) {
//!     println!("size: {}", entry.size);
//! }
//!
//! // Content reads still go to disk via the VFS.
//! let bytes = vfs.read_file_range(Path::new("/Windows/System32/cmd.exe"), 0, 4096)?;
//! ```

use crate::errors::ForensicError;
use crate::virtualization::{VfsEntry, VirtualFileSystem};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Hard cap on the number of entries any single walk will index. A bound
/// prevents runaway indexing on hostile or corrupted images that report
/// directory cycles. 50M is large enough for any realistic evidence image
/// (a 2 TB NTFS volume rarely exceeds 5–10M files).
pub const MAX_SNAPSHOT_ENTRIES: usize = 50_000_000;

/// Maximum directory depth that will be walked. Defends against pathological
/// recursive cycles in damaged filesystems.
pub const MAX_WALK_DEPTH: usize = 1024;

/// One indexed entry in a [`VolumeSnapshot`].
///
/// Mirrors [`VfsEntry`] plus a slot for the underlying inode / MFT record
/// number when the source filesystem exposes one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
    /// Inode / MFT record number when the filesystem reports one.
    /// `None` for filesystems that don't expose inodes (RAW, ISO, etc).
    pub inode: Option<u64>,
}

impl From<&VfsEntry> for SnapshotEntry {
    fn from(e: &VfsEntry) -> Self {
        Self {
            name: e.name.clone(),
            path: e.path.clone(),
            is_dir: e.is_dir,
            size: e.size,
            modified: e.modified,
            inode: None,
        }
    }
}

/// Statistics about a built snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotStats {
    pub file_count: u64,
    pub directory_count: u64,
    pub total_bytes: u64,
    pub max_depth_seen: usize,
    /// `true` if the walk hit `MAX_SNAPSHOT_ENTRIES` or `MAX_WALK_DEPTH`
    /// and stopped early. Callers should warn the examiner.
    pub truncated: bool,
}

/// In-memory metadata index for a forensic evidence VFS.
///
/// A `VolumeSnapshot` is built once via [`VolumeSnapshot::build_from_vfs`]
/// and then queried for the lifetime of the case. All metadata queries are
/// O(1) `HashMap` lookups — no disk I/O is performed for metadata. Use
/// [`VirtualFileSystem::read_file_range`] directly on the underlying VFS
/// for any actual byte reads.
#[derive(Debug, Clone, Default)]
pub struct VolumeSnapshot {
    /// Path → metadata. Path keys are normalized (no `.` components,
    /// never empty), so a query against any path that walked the source
    /// VFS returns the same canonical key.
    entries: HashMap<PathBuf, SnapshotEntry>,
    /// Lookup of inode → path for filesystems that expose inode numbers.
    inode_index: HashMap<u64, PathBuf>,
    /// Build statistics.
    stats: SnapshotStats,
    /// Root path the snapshot was built from.
    root: PathBuf,
}

impl VolumeSnapshot {
    /// Build a snapshot by walking every directory of `vfs` starting at
    /// `vfs.root()`. Subsequent metadata queries can be served from the
    /// returned snapshot in O(1) with no disk reads.
    pub fn build_from_vfs(vfs: &dyn VirtualFileSystem) -> Result<Self, ForensicError> {
        let root = vfs.root().clone();
        Self::build_from_vfs_at(vfs, &root)
    }

    /// Build a snapshot starting at a specific subtree of the VFS.
    pub fn build_from_vfs_at(
        vfs: &dyn VirtualFileSystem,
        start: &Path,
    ) -> Result<Self, ForensicError> {
        let mut snap = VolumeSnapshot {
            root: start.to_path_buf(),
            ..Default::default()
        };

        // Seed the root entry so `metadata(root)` works after build.
        let root_key = normalize(start);
        snap.entries.insert(
            root_key.clone(),
            SnapshotEntry {
                name: start
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| root_key.to_string_lossy().into_owned()),
                path: start.to_path_buf(),
                is_dir: true,
                size: 0,
                modified: None,
                inode: None,
            },
        );
        snap.stats.directory_count += 1;

        // Iterative BFS — avoids unbounded stack growth on deep trees.
        let mut queue: Vec<(PathBuf, usize)> = vec![(start.to_path_buf(), 0)];

        while let Some((dir, depth)) = queue.pop() {
            if depth > snap.stats.max_depth_seen {
                snap.stats.max_depth_seen = depth;
            }
            if depth >= MAX_WALK_DEPTH {
                snap.stats.truncated = true;
                continue;
            }
            if snap.entries.len() >= MAX_SNAPSHOT_ENTRIES {
                snap.stats.truncated = true;
                break;
            }

            // Skip unreadable directories rather than aborting the entire
            // walk — partial coverage is better than nothing on corrupt
            // images.
            let listing = match vfs.read_dir(&dir) {
                Ok(v) => v,
                Err(_) => continue,
            };

            for entry in listing {
                let key = normalize(&entry.path);
                let snap_entry = SnapshotEntry::from(&entry);
                if entry.is_dir {
                    snap.stats.directory_count += 1;
                    queue.push((entry.path.clone(), depth + 1));
                } else {
                    snap.stats.file_count += 1;
                    snap.stats.total_bytes = snap.stats.total_bytes.saturating_add(entry.size);
                }
                snap.entries.insert(key, snap_entry);

                if snap.entries.len() >= MAX_SNAPSHOT_ENTRIES {
                    snap.stats.truncated = true;
                    break;
                }
            }
        }

        Ok(snap)
    }

    /// Build a snapshot from a pre-collected slice of `VfsEntry` records.
    /// Useful for tests and for cases where the caller already walked the
    /// tree (for example, NTFS MFT enumeration that returns every entry
    /// in one pass).
    pub fn from_entries(root: PathBuf, entries: &[VfsEntry]) -> Self {
        let mut snap = VolumeSnapshot {
            root: root.clone(),
            ..Default::default()
        };
        snap.entries.insert(
            normalize(&root),
            SnapshotEntry {
                name: root
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                path: root.clone(),
                is_dir: true,
                size: 0,
                modified: None,
                inode: None,
            },
        );
        snap.stats.directory_count += 1;
        for e in entries {
            let snap_entry = SnapshotEntry::from(e);
            if e.is_dir {
                snap.stats.directory_count += 1;
            } else {
                snap.stats.file_count += 1;
                snap.stats.total_bytes = snap.stats.total_bytes.saturating_add(e.size);
            }
            snap.entries.insert(normalize(&e.path), snap_entry);
        }
        snap
    }

    /// Number of indexed entries (files + directories, including the root).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the snapshot has not indexed any entries at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Build statistics for the walk that produced this snapshot.
    pub fn stats(&self) -> &SnapshotStats {
        &self.stats
    }

    /// Path that this snapshot was built from.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Query metadata by path. Returns `None` if the path was not visited
    /// during the build walk. This is the hot-path query — O(1), no disk
    /// I/O.
    pub fn metadata(&self, path: &Path) -> Option<&SnapshotEntry> {
        self.entries.get(&normalize(path))
    }

    /// True if `path` was indexed.
    pub fn contains(&self, path: &Path) -> bool {
        self.entries.contains_key(&normalize(path))
    }

    /// Iterate every indexed entry.
    pub fn iter(&self) -> impl Iterator<Item = &SnapshotEntry> {
        self.entries.values()
    }

    /// Iterate file entries only (skips directories).
    pub fn files(&self) -> impl Iterator<Item = &SnapshotEntry> {
        self.entries.values().filter(|e| !e.is_dir)
    }

    /// Iterate directory entries only.
    pub fn directories(&self) -> impl Iterator<Item = &SnapshotEntry> {
        self.entries.values().filter(|e| e.is_dir)
    }

    /// Lookup an entry by inode number. Only useful for snapshots built
    /// (or enriched) from filesystems that expose inodes — see
    /// [`VolumeSnapshot::upsert`].
    pub fn lookup_inode(&self, inode: u64) -> Option<&SnapshotEntry> {
        self.inode_index
            .get(&inode)
            .and_then(|p| self.entries.get(p))
    }

    /// Insert or replace an entry. Used by filesystem-specific code that
    /// wants to enrich the base snapshot with inode numbers from the MFT
    /// or an inode table.
    pub fn upsert(&mut self, entry: SnapshotEntry) {
        let key = normalize(&entry.path);
        if let Some(inode) = entry.inode {
            self.inode_index.insert(inode, key.clone());
        }
        self.entries.insert(key, entry);
    }
}

/// Normalize a path for use as a `HashMap` key. Strips `.` components and
/// never returns an empty path.
fn normalize(p: &Path) -> PathBuf {
    use std::path::Component;

    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            _ => out.push(comp),
        }
    }
    if out.as_os_str().is_empty() {
        out.push("/");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Mutex;

    /// Mock VFS used in tests. Stores a fixed file/dir layout in memory and
    /// counts every `read_dir` call so we can prove the snapshot serves
    /// later metadata queries from the index, not from the underlying VFS.
    struct MockVfs {
        root: PathBuf,
        layout: HashMap<PathBuf, Vec<VfsEntry>>,
        all: HashMap<PathBuf, VfsEntry>,
        read_dir_calls: Mutex<usize>,
    }

    impl MockVfs {
        fn new() -> Self {
            let root = PathBuf::from("/");

            let mk_dir = |name: &str, path: &str| VfsEntry {
                name: name.to_string(),
                path: PathBuf::from(path),
                is_dir: true,
                size: 0,
                modified: None,
            };
            let mk_file = |name: &str, path: &str, size: u64| VfsEntry {
                name: name.to_string(),
                path: PathBuf::from(path),
                is_dir: false,
                size,
                modified: Some(Utc.with_ymd_and_hms(2026, 4, 9, 12, 0, 0).unwrap()),
            };

            let mut layout: HashMap<PathBuf, Vec<VfsEntry>> = HashMap::new();
            layout.insert(
                PathBuf::from("/"),
                vec![
                    mk_dir("windows", "/windows"),
                    mk_file("readme.txt", "/readme.txt", 1024),
                ],
            );
            layout.insert(
                PathBuf::from("/windows"),
                vec![
                    mk_dir("system32", "/windows/system32"),
                    mk_file("explorer.exe", "/windows/explorer.exe", 4_500_000),
                ],
            );
            layout.insert(
                PathBuf::from("/windows/system32"),
                vec![
                    mk_file("kernel32.dll", "/windows/system32/kernel32.dll", 750_000),
                    mk_file("ntdll.dll", "/windows/system32/ntdll.dll", 1_900_000),
                ],
            );

            let mut all: HashMap<PathBuf, VfsEntry> = HashMap::new();
            for entries in layout.values() {
                for e in entries {
                    all.insert(e.path.clone(), e.clone());
                }
            }

            Self {
                root,
                layout,
                all,
                read_dir_calls: Mutex::new(0),
            }
        }

        fn read_dir_count(&self) -> usize {
            *self.read_dir_calls.lock().unwrap()
        }
    }

    impl VirtualFileSystem for MockVfs {
        fn root(&self) -> &PathBuf {
            &self.root
        }
        fn read_dir(&self, path: &Path) -> Result<Vec<VfsEntry>, ForensicError> {
            *self.read_dir_calls.lock().unwrap() += 1;
            self.layout
                .get(path)
                .cloned()
                .ok_or_else(|| ForensicError::NotFound(format!("dir {:?}", path)))
        }
        fn open_file(&self, _path: &Path) -> Result<Vec<u8>, ForensicError> {
            Ok(Vec::new())
        }
        fn file_metadata(&self, path: &Path) -> Result<VfsEntry, ForensicError> {
            self.all
                .get(path)
                .cloned()
                .ok_or_else(|| ForensicError::NotFound(format!("meta {:?}", path)))
        }
        fn total_size(&self) -> u64 {
            0
        }
        fn read_volume_at(&self, _offset: u64, _size: usize) -> Result<Vec<u8>, ForensicError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn snapshot_builds_full_tree() {
        let vfs = MockVfs::new();
        let snap = VolumeSnapshot::build_from_vfs(&vfs).expect("build");

        // Root + 2 child dirs (/windows, /windows/system32) + 4 files
        assert!(snap.contains(Path::new("/")));
        assert!(snap.contains(Path::new("/windows")));
        assert!(snap.contains(Path::new("/windows/system32")));
        assert!(snap.contains(Path::new("/readme.txt")));
        assert!(snap.contains(Path::new("/windows/explorer.exe")));
        assert!(snap.contains(Path::new("/windows/system32/kernel32.dll")));
        assert!(snap.contains(Path::new("/windows/system32/ntdll.dll")));

        assert_eq!(snap.stats().file_count, 4);
        assert_eq!(snap.stats().directory_count, 3); // root + 2 children
        assert_eq!(
            snap.stats().total_bytes,
            1024 + 4_500_000 + 750_000 + 1_900_000
        );
        assert!(!snap.stats().truncated);
    }

    #[test]
    fn snapshot_metadata_matches_direct_vfs_query() {
        let vfs = MockVfs::new();
        let snap = VolumeSnapshot::build_from_vfs(&vfs).expect("build");

        for path in [
            "/readme.txt",
            "/windows/explorer.exe",
            "/windows/system32/kernel32.dll",
            "/windows/system32/ntdll.dll",
        ] {
            let direct = vfs.file_metadata(Path::new(path)).unwrap();
            let snap_entry = snap.metadata(Path::new(path)).expect("indexed");
            assert_eq!(snap_entry.name, direct.name);
            assert_eq!(snap_entry.size, direct.size);
            assert_eq!(snap_entry.is_dir, direct.is_dir);
            assert_eq!(snap_entry.modified, direct.modified);
        }
    }

    #[test]
    fn snapshot_metadata_queries_do_not_hit_vfs() {
        let vfs = MockVfs::new();
        let snap = VolumeSnapshot::build_from_vfs(&vfs).expect("build");
        let read_dirs_after_build = vfs.read_dir_count();
        assert!(read_dirs_after_build > 0);

        for _ in 0..1_000 {
            assert!(snap.metadata(Path::new("/readme.txt")).is_some());
            assert!(snap
                .metadata(Path::new("/windows/system32/ntdll.dll"))
                .is_some());
            assert!(snap.metadata(Path::new("/missing/path")).is_none());
        }

        // Zero new read_dir() calls — the snapshot is serving every
        // query from its in-memory index.
        assert_eq!(vfs.read_dir_count(), read_dirs_after_build);
    }

    #[test]
    fn snapshot_inode_index_round_trips() {
        let mut snap = VolumeSnapshot::default();
        snap.upsert(SnapshotEntry {
            name: "$MFT".to_string(),
            path: PathBuf::from("/$MFT"),
            is_dir: false,
            size: 4096,
            modified: None,
            inode: Some(0),
        });

        let by_inode = snap.lookup_inode(0).expect("inode lookup");
        assert_eq!(by_inode.name, "$MFT");
        assert_eq!(by_inode.size, 4096);
    }

    #[test]
    fn snapshot_iter_partitions_files_and_dirs() {
        let vfs = MockVfs::new();
        let snap = VolumeSnapshot::build_from_vfs(&vfs).expect("build");

        let file_count = snap.files().count();
        let dir_count = snap.directories().count();
        assert_eq!(file_count, 4);
        assert_eq!(dir_count, 3);
        assert_eq!(file_count + dir_count, snap.len());
    }

    #[test]
    fn from_entries_builds_equivalent_snapshot() {
        let vfs = MockVfs::new();
        let walked = VolumeSnapshot::build_from_vfs(&vfs).expect("walk");

        // Collect every entry the walker indexed and rebuild from them.
        let collected: Vec<VfsEntry> = walked
            .iter()
            .filter(|e| e.path != Path::new("/"))
            .map(|e| VfsEntry {
                name: e.name.clone(),
                path: e.path.clone(),
                is_dir: e.is_dir,
                size: e.size,
                modified: e.modified,
            })
            .collect();
        let rebuilt = VolumeSnapshot::from_entries(PathBuf::from("/"), &collected);

        assert_eq!(rebuilt.len(), walked.len());
        for entry in walked.iter() {
            let other = rebuilt.metadata(&entry.path).expect("present");
            assert_eq!(other.size, entry.size);
            assert_eq!(other.is_dir, entry.is_dir);
        }
    }

    #[test]
    fn snapshot_path_normalization_handles_curdir() {
        let vfs = MockVfs::new();
        let snap = VolumeSnapshot::build_from_vfs(&vfs).expect("build");

        // `/./readme.txt` should resolve to the same key as `/readme.txt`.
        assert!(snap.metadata(Path::new("/./readme.txt")).is_some());
        assert!(snap
            .metadata(Path::new("/windows/./system32/kernel32.dll"))
            .is_some());
    }
}

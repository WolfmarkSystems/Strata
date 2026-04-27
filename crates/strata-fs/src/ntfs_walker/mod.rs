//! FS-NTFS-1 + FS-NTFS-2 — NTFS walker built on the `ntfs` crate.
//!
//! Evaluation: `ntfs = "0.4"` (Colin Finck, MIT/Apache-2.0, pure-Rust,
//! read-only by design, no_std-compatible). The crate exposes
//! `Ntfs::new(&mut fs) -> NtfsResult<Ntfs>` which takes any type
//! implementing `Read + Seek`. That shape is a clean fit for our
//! `VirtualFilesystem` trait once the reader is behind a `Mutex` so
//! `&self` methods can mutate it during reads.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

pub mod adapter;

use std::io::{BufReader, Read, Seek};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeZone, Utc};
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::{Ntfs, NtfsAttributeType, NtfsFile, NtfsReadSeek};
use strata_evidence::EvidenceImage;

use crate::vfs::{
    VfsAttributes, VfsEntry, VfsError, VfsMetadata, VfsResult, VfsSpecific, VirtualFilesystem,
};

pub use adapter::PartitionReader;

/// `Send + Sync` NTFS walker that speaks the VFS trait. Internally
/// serialises reader access through a `Mutex` because the `ntfs`
/// crate mutates the reader during attribute traversal.
pub struct NtfsWalker {
    state: Mutex<NtfsState<BufReader<PartitionReader>>>,
}

struct NtfsState<R: Read + Seek> {
    ntfs: Ntfs,
    reader: R,
}

impl NtfsWalker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> VfsResult<Self> {
        let sector_size = image.sector_size().max(512) as usize;
        let raw = PartitionReader::new(image, partition_offset, partition_size, sector_size);
        let mut reader = BufReader::with_capacity(128 * 1024, raw);
        let mut ntfs =
            Ntfs::new(&mut reader).map_err(|e| VfsError::Other(format!("ntfs open: {e}")))?;
        // Populate the Upcase table so case-insensitive operations work.
        let _ = ntfs.read_upcase_table(&mut reader);
        Ok(Self {
            state: Mutex::new(NtfsState { ntfs, reader }),
        })
    }
}

fn normalize_path(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn ntfs_time_to_utc(ts: ntfs::NtfsTime) -> Option<DateTime<Utc>> {
    // NtfsTime stores 100-ns intervals since 1601-01-01. Convert to
    // unix seconds.
    let val = ts.nt_timestamp();
    const WINDOWS_TICK: i64 = 10_000_000;
    const SEC_TO_UNIX_EPOCH: i64 = 11_644_473_600;
    let secs = (val as i64 / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH;
    Utc.timestamp_opt(secs, 0).single()
}

fn file_to_entry<T: Read + Seek>(
    ntfs: &Ntfs,
    reader: &mut T,
    file: &NtfsFile<'_>,
    parent_path: &str,
) -> VfsResult<VfsEntry> {
    let info = file
        .info()
        .map_err(|e| VfsError::Other(format!("ntfs info: {e}")))?;
    let name = best_file_name(ntfs, reader, file).unwrap_or_default();
    let is_dir = file.is_directory();
    let created = ntfs_time_to_utc(info.creation_time());
    let modified = ntfs_time_to_utc(info.modification_time());
    let accessed = ntfs_time_to_utc(info.access_time());
    let mft_changed = ntfs_time_to_utc(info.mft_record_modification_time());
    let path = if parent_path == "/" || parent_path.is_empty() {
        format!("/{name}")
    } else {
        format!("{}/{}", parent_path.trim_end_matches('/'), name)
    };
    let size = file_size(ntfs, reader, file);
    let attrs_flags = info.file_attributes().bits();
    let attributes = VfsAttributes {
        readonly: attrs_flags & 0x0000_0001 != 0,
        hidden: attrs_flags & 0x0000_0002 != 0,
        system: attrs_flags & 0x0000_0004 != 0,
        archive: attrs_flags & 0x0000_0020 != 0,
        compressed: attrs_flags & 0x0000_0800 != 0,
        encrypted: attrs_flags & 0x0000_4000 != 0,
        sparse: attrs_flags & 0x0000_0200 != 0,
        unix_mode: None,
        unix_uid: None,
        unix_gid: None,
    };
    Ok(VfsEntry {
        path,
        name,
        is_directory: is_dir,
        size,
        created,
        modified,
        accessed,
        metadata_changed: mft_changed,
        attributes,
        inode_number: Some(file.file_record_number()),
        has_alternate_streams: false,
        fs_specific: VfsSpecific::Ntfs {
            mft_record: file.file_record_number(),
            resident: false,
        },
    })
}

fn best_file_name<T: Read + Seek>(
    _ntfs: &Ntfs,
    _reader: &mut T,
    file: &NtfsFile<'_>,
) -> Option<String> {
    // Iterate FILE_NAME attributes and pick the most usable one:
    // prefer Win32 over DOS 8.3.
    let attrs = file.attributes_raw();
    let mut best_win32: Option<String> = None;
    let mut best_any: Option<String> = None;
    for attr_res in attrs {
        let Ok(attr) = attr_res else { continue };
        if attr.ty().ok()? != NtfsAttributeType::FileName {
            continue;
        }
        let Ok(structured) =
            attr.structured_value::<T, ntfs::structured_values::NtfsFileName>(_reader)
        else {
            continue;
        };
        let ns = structured.namespace();
        let name_str = structured.name().to_string_lossy();
        if best_any.is_none() {
            best_any = Some(name_str.clone());
        }
        if matches!(
            ns,
            ntfs::structured_values::NtfsFileNamespace::Win32
                | ntfs::structured_values::NtfsFileNamespace::Win32AndDos
                | ntfs::structured_values::NtfsFileNamespace::Posix
        ) {
            best_win32 = Some(name_str);
            break;
        }
    }
    best_win32.or(best_any)
}

fn file_size<T: Read + Seek>(_ntfs: &Ntfs, reader: &mut T, file: &NtfsFile<'_>) -> u64 {
    // Size lives on the unnamed $DATA attribute for files; directories
    // return 0. Iterate attributes looking for Data.
    let mut size = 0u64;
    for attr_res in file.attributes_raw() {
        let Ok(attr) = attr_res else { continue };
        if matches!(attr.ty(), Ok(NtfsAttributeType::Data))
            && attr.name().ok().map(|n| n.is_empty()).unwrap_or(false)
        {
            if let Ok(value) = attr.value(reader) {
                size = value.len();
                break;
            }
        }
    }
    size
}

fn directory_file<'a, T: Read + Seek>(
    ntfs: &'a Ntfs,
    reader: &mut T,
    path: &str,
) -> VfsResult<NtfsFile<'a>> {
    let mut current = ntfs
        .root_directory(reader)
        .map_err(|e| VfsError::Other(format!("ntfs root: {e}")))?;
    for part in normalize_path(path) {
        let index = current
            .directory_index(reader)
            .map_err(|e| VfsError::Other(format!("ntfs index: {e}")))?;
        let mut finder = index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, ntfs, reader, &part);
        let entry = match entry {
            Some(Ok(e)) => e,
            _ => return Err(VfsError::NotFound(path.into())),
        };
        let file = entry
            .to_file(ntfs, reader)
            .map_err(|e| VfsError::Other(format!("ntfs to_file: {e}")))?;
        current = file;
    }
    Ok(current)
}

impl VirtualFilesystem for NtfsWalker {
    fn fs_type(&self) -> &'static str {
        "ntfs"
    }

    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let mut guard = self
            .state
            .lock()
            .map_err(|e| VfsError::Other(format!("ntfs poisoned: {e}")))?;
        let state = &mut *guard;
        let dir = directory_file(&state.ntfs, &mut state.reader, path)?;
        if !dir.is_directory() {
            return Err(VfsError::NotADirectory(path.into()));
        }
        let index = dir
            .directory_index(&mut state.reader)
            .map_err(|e| VfsError::Other(format!("ntfs index: {e}")))?;
        let mut iter = index.entries();
        let mut out: Vec<VfsEntry> = Vec::new();
        while let Some(entry_res) = iter.next(&mut state.reader) {
            let Ok(entry) = entry_res else { continue };
            let Some(Ok(fname_attr)) = entry.key() else {
                continue;
            };
            let name_lossy = fname_attr.name().to_string_lossy();
            if name_lossy == "." || name_lossy == ".." {
                continue;
            }
            // Skip DOS 8.3 short-name-only entries when a Win32 name
            // exists for the same file (avoids duplicates).
            if matches!(
                fname_attr.namespace(),
                ntfs::structured_values::NtfsFileNamespace::Dos
            ) {
                continue;
            }
            let file = match entry.to_file(&state.ntfs, &mut state.reader) {
                Ok(f) => f,
                Err(_) => continue,
            };
            if let Ok(e) = file_to_entry(&state.ntfs, &mut state.reader, &file, path) {
                out.push(e);
            }
        }
        Ok(out)
    }

    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let mut guard = self
            .state
            .lock()
            .map_err(|e| VfsError::Other(format!("ntfs poisoned: {e}")))?;
        let state = &mut *guard;
        let file = directory_file(&state.ntfs, &mut state.reader, path)?;
        if file.is_directory() {
            return Err(VfsError::NotAFile(path.into()));
        }
        let mut out = Vec::new();
        for attr_res in file.attributes_raw() {
            let Ok(attr) = attr_res else { continue };
            if !matches!(attr.ty(), Ok(NtfsAttributeType::Data)) {
                continue;
            }
            if !attr.name().ok().map(|n| n.is_empty()).unwrap_or(false) {
                continue;
            }
            let Ok(value) = attr.value(&mut state.reader) else {
                continue;
            };
            let mut value = value;
            let mut buf = vec![0u8; value.len() as usize];
            value
                .read_exact(&mut state.reader, &mut buf)
                .map_err(|e| VfsError::Other(format!("ntfs read: {e}")))?;
            out = buf;
            break;
        }
        Ok(out)
    }

    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> {
        let mut guard = self
            .state
            .lock()
            .map_err(|e| VfsError::Other(format!("ntfs poisoned: {e}")))?;
        let state = &mut *guard;
        let file = directory_file(&state.ntfs, &mut state.reader, path)?;
        let entry = file_to_entry(&state.ntfs, &mut state.reader, &file, "/")?;
        Ok(VfsMetadata {
            size: entry.size,
            is_directory: entry.is_directory,
            created: entry.created,
            modified: entry.modified,
            accessed: entry.accessed,
            attributes: entry.attributes,
        })
    }

    fn exists(&self, path: &str) -> bool {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let state = &mut *guard;
        directory_file(&state.ntfs, &mut state.reader, path).is_ok()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use strata_evidence::{EvidenceImage, EvidenceResult, ImageMetadata};

    struct MemImage {
        bytes: Vec<u8>,
    }
    impl EvidenceImage for MemImage {
        fn size(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn format_name(&self) -> &'static str {
            "MemImage"
        }
        fn metadata(&self) -> ImageMetadata {
            ImageMetadata::minimal("MemImage", self.bytes.len() as u64, 512)
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> EvidenceResult<usize> {
            let o = offset as usize;
            if o >= self.bytes.len() {
                return Ok(0);
            }
            let n = (self.bytes.len() - o).min(buf.len());
            buf[..n].copy_from_slice(&self.bytes[o..o + n]);
            Ok(n)
        }
    }

    #[test]
    fn open_rejects_non_ntfs_image() {
        let img: Arc<dyn EvidenceImage> = Arc::new(MemImage {
            bytes: vec![0u8; 16 * 1024],
        });
        let size = img.size();
        let res = NtfsWalker::open(img, 0, size);
        assert!(res.is_err());
    }

    #[test]
    fn adapter_reads_partition_window() {
        let img: Arc<dyn EvidenceImage> = Arc::new(MemImage {
            bytes: (0..200u8).collect(),
        });
        let mut view = PartitionReader::new(img, 50, 100, 512);
        use std::io::Read as _;
        let mut buf = vec![0u8; 10];
        let n = view.read(&mut buf).expect("read");
        assert_eq!(n, 10);
        assert_eq!(buf[0], 50);
        assert_eq!(buf[9], 59);
    }

    #[test]
    fn filetime_conversion_landmark() {
        // NTFS filetime for 2024-01-01T00:00:00Z is 133_485_408_000_000_000.
        let nt = ntfs::NtfsTime::from(133_485_408_000_000_000u64);
        let dt = ntfs_time_to_utc(nt).expect("dt");
        assert_eq!(dt.timestamp(), 1_704_067_200);
    }

    #[test]
    fn normalize_path_strips_slashes() {
        assert!(normalize_path("/").is_empty());
        assert_eq!(normalize_path("/a/b/c"), vec!["a", "b", "c"]);
    }
}

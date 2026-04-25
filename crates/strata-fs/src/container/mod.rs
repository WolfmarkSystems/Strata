pub mod aff4;
pub mod audited;
pub mod core_storage;
pub mod dmg;
pub mod e01;
pub mod filevault;
pub mod ingest_registry;
pub mod iso;
pub mod l01;
pub mod luks;
pub mod lvm;
pub mod policy;
pub mod qcow2;
pub mod raw;
pub mod sparsebundle;
pub mod split_raw;
pub mod storage_spaces;
pub mod triage;
pub mod vdi;
pub mod vhd;
pub mod vmdk;

pub use aff4::{open_aff4, Aff4Container};
pub use audited::AuditedContainer;
pub use core_storage::{parse_core_storage, CoreStorageVolume};
pub use filevault::{parse_filevault, FileVaultContainer};
pub use ingest_registry::{IngestDescriptor, IngestProfile, IngestRegistry};
pub use iso::IsoContainer;
pub use l01::{open_l01, L01Container};
pub use luks::{open_luks, LuksContainer};
pub use lvm::{parse_lvm, LvmState};
pub use policy::ReadPolicyContainer;
pub use qcow2::{open_qcow2, Qcow2Container};
pub use raw::RawContainer;
pub use split_raw::SplitRawContainer;
pub use storage_spaces::{parse_storage_spaces, StorageSpacesPool};
pub use triage::{open_triage, TriageContainer};
pub use vdi::{open_vdi, VdiContainer};
pub use vhd::{open_vhd, open_vhdx, VhdContainer, VhdxContainer};
pub use vmdk::{open_vmdk, VmdkContainer};

use crate::errors::ForensicError;
use crate::virtualization::EwfVfs;
use crate::virtualization::ImageFormat;
use crate::virtualization::{
    Aff4Vfs, FsVfs, IsoVfs, Qcow2Vfs, RawVfs, SplitRawVfs, VhdVfs, VirtualFileSystem, VmdkVfs,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Read-only evidence container trait (core abstraction).
///
/// Performance hardening:
/// - `read_into` allows callers (hashing) to reuse buffers for X-Ways-level throughput.
/// - `read_at` remains as a convenience API and is implemented via `read_into` by default.
pub trait EvidenceContainerRO: Send + Sync {
    fn description(&self) -> &str;
    fn source_path(&self) -> &Path;
    fn size(&self) -> u64;
    fn sector_size(&self) -> u64;

    /// Non-allocating read into caller-provided buffer.
    /// Implementers should do position-independent reads (pread/seek_read) when possible.
    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError>;

    /// Allocating read helper (default uses read_into).
    fn read_at(&self, offset: u64, length: u64) -> Result<Vec<u8>, ForensicError> {
        if length == 0 {
            return Ok(Vec::new());
        }

        let len_usize: usize = length.try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "read length too large")
        })?;

        let mut v = vec![0u8; len_usize];
        self.read_into(offset, &mut v)?;
        Ok(v)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerType {
    Directory,
    Raw,
    E01,
    Aff,
    Vmdk,
    Vhd,
    Vhdx,
    Iso,
    SplitRaw,
    Qcow2,
    /// Cellebrite UFED export: a directory containing `.ufd` / `.ufdx`
    /// metadata and an `EXTRACTION_FFS.zip` payload. FIX-2.
    Ufed,
    /// Cellebrite UFDR report package: `.ufdr` file, or a directory
    /// containing `report.xml` with a Cellebrite signature. FIX-2.
    Ufdr,
    /// ZIP archive (e.g. Hexordia CTF MacBookPro.zip). Sprint-9 P3:
    /// extracted lazily into a scratch directory by `EvidenceSource::open`,
    /// then walked as `ContainerType::Directory` via `FsVfs`.
    ArchiveZip,
    /// TAR / TAR.GZ / TGZ archive. Sprint-9 P3: same extract-to-scratch
    /// pipeline as `ArchiveZip`. Decompression is handled by `UnpackEngine`.
    ArchiveTar,
}

impl ContainerType {
    pub fn from_path(path: &Path) -> Self {
        let format = ImageFormat::from_path(path);
        match format {
            ImageFormat::RAW | ImageFormat::DD | ImageFormat::SplitRaw => ContainerType::Raw,
            ImageFormat::E01 => ContainerType::E01,
            ImageFormat::AFF
            | ImageFormat::AFF4
            | ImageFormat::S01
            | ImageFormat::Lx01
            | ImageFormat::Lx02 => ContainerType::Aff,
            ImageFormat::VMDK => ContainerType::Vmdk,
            ImageFormat::VHD => ContainerType::Vhd,
            ImageFormat::VHDX => ContainerType::Vhdx,
            ImageFormat::ISO => ContainerType::Iso,
            _ => ContainerType::Raw,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ContainerType::Directory => "Directory",
            ContainerType::Raw => "RAW/DD",
            ContainerType::E01 => "E01 (EnCase)",
            ContainerType::Aff => "AFF",
            ContainerType::Vmdk => "VMDK",
            ContainerType::Vhd => "VHD",
            ContainerType::Vhdx => "VHDX",
            ContainerType::Iso => "ISO",
            ContainerType::SplitRaw => "Split RAW",
            ContainerType::Qcow2 => "QCOW2",
            ContainerType::Ufed => "UFED (Cellebrite export)",
            ContainerType::Ufdr => "UFDR (Cellebrite report package)",
            ContainerType::ArchiveZip => "ZIP archive",
            ContainerType::ArchiveTar => "TAR archive",
        }
    }

    pub fn is_container(&self) -> bool {
        !matches!(self, ContainerType::Directory)
    }
}

pub struct EvidenceSource {
    pub path: PathBuf,
    pub container_type: ContainerType,
    pub vfs: Option<Box<dyn VirtualFileSystem>>,
    pub size: u64,
}

impl EvidenceSource {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let descriptor = IngestRegistry::detect(path);
        let container_type = descriptor.container_type;
        log::debug!(
            "EvidenceSource open: path={:?}, detected_type={:?}",
            path,
            container_type
        );

        let mut size = if path.is_dir() {
            0
        } else {
            std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
        };

        let vfs: Option<Box<dyn VirtualFileSystem>> = match container_type {
            ContainerType::Directory => {
                let fs_vfs = FsVfs::new(path.to_path_buf());
                Some(Box::new(fs_vfs))
            }
            ContainerType::E01 => {
                let ewf_vfs = EwfVfs::new(path)?;
                Some(Box::new(ewf_vfs))
            }
            ContainerType::Raw => {
                let raw_vfs = RawVfs::new(path)?;
                Some(Box::new(raw_vfs))
            }
            ContainerType::Vmdk => {
                let vmdk_vfs = VmdkVfs::new(path)?;
                Some(Box::new(vmdk_vfs))
            }
            ContainerType::Aff => {
                let a_vfs = Aff4Vfs::new(path)?;
                Some(Box::new(a_vfs))
            }
            ContainerType::Iso => {
                let iso_vfs = IsoVfs::new(path)?;
                Some(Box::new(iso_vfs))
            }
            ContainerType::Qcow2 => {
                let q_vfs = Qcow2Vfs::new(path)?;
                Some(Box::new(q_vfs))
            }
            ContainerType::SplitRaw => {
                let s_vfs = SplitRawVfs::new(path)?;
                Some(Box::new(s_vfs))
            }
            ContainerType::Vhd | ContainerType::Vhdx => {
                let vhd_vfs = VhdVfs::new(path)?;
                Some(Box::new(vhd_vfs))
            }
            // UFED / UFDR are logical exports: the examiner-visible tree
            // is the directory tree on disk. We reuse FsVfs so plugins see
            // a normal filesystem; container metadata (`.ufdx`, `.ufd`,
            // `report.xml`) is still parsed by `strata-core::parsers::ufdr`
            // and the `ios::cellebrite` parser through the plugin path.
            ContainerType::Ufed | ContainerType::Ufdr => {
                let fs_vfs = FsVfs::new(path.to_path_buf());
                Some(Box::new(fs_vfs))
            }
            // Sprint-9 P3: ZIP / TAR archive ingestion. Extract once into
            // a deterministic scratch dir (keyed by archive path hash so
            // re-opening the same archive is idempotent), then walk the
            // extracted tree via FsVfs — identical to the folder path.
            ContainerType::ArchiveZip | ContainerType::ArchiveTar => {
                let extracted = ensure_archive_extracted(path)?;
                size = 0;
                let fs_vfs = FsVfs::new(extracted);
                Some(Box::new(fs_vfs))
            }
        };

        if let Some(ref v) = vfs {
            size = v.total_size();
        }

        Ok(Self {
            path: path.to_path_buf(),
            container_type,
            vfs,
            size,
        })
    }

    pub fn is_container(&self) -> bool {
        self.container_type.is_container()
    }

    pub fn vfs_ref(&self) -> Option<&dyn VirtualFileSystem> {
        self.vfs.as_deref()
    }
}

pub fn open_evidence_container(path: &Path) -> Result<EvidenceSource, ForensicError> {
    EvidenceSource::open(path)
}

/// Sprint-9 P3 helper. Extract the archive at `archive_path` into a
/// deterministic scratch directory under the system temp root, returning
/// the path that should be walked as a filesystem.
///
/// Idempotent: if a previous run already populated the scratch directory
/// the archive is *not* re-extracted (avoids redundant disk I/O when the
/// examiner reopens the same evidence).
///
/// Encrypted archives are surfaced as `ForensicError::UnsupportedFormat`
/// rather than silently producing an empty directory — examiners need to
/// know they have to provide the password through a third-party tool
/// before reopening in Strata.
fn ensure_archive_extracted(archive_path: &Path) -> Result<std::path::PathBuf, ForensicError> {
    use crate::unpack::{unpack, UnpackEngine, UnpackWarning};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    archive_path.to_string_lossy().hash(&mut hasher);
    let key = format!("{:016x}", hasher.finish());
    let scratch = std::env::temp_dir().join("strata-archives").join(&key);
    let leaf = scratch.join("layer_0");

    // Idempotency: a populated `layer_0` from a prior run is reused.
    let already_extracted = leaf.is_dir()
        && std::fs::read_dir(&leaf)
            .map(|mut it| it.next().is_some())
            .unwrap_or(false);
    if already_extracted {
        log::debug!(
            "Archive {:?} reusing extracted scratch at {:?}",
            archive_path,
            leaf
        );
        return Ok(leaf);
    }

    std::fs::create_dir_all(&scratch)?;

    // Forensic archives (e.g. the 82 GB Hexordia MacBookPro.zip) routinely
    // exceed the unpack engine's 2 GiB default cap. Examiners explicitly
    // chose this archive — the cap exists to defend against zip bombs in
    // automated/recursive contexts, not to throttle deliberate ingestion.
    // Bump to 1 TiB (still bounded, still trips runaway nested archives).
    let engine = UnpackEngine::new(scratch.clone())
        .with_max_total_bytes(1024 * 1024 * 1024 * 1024);
    let result = unpack(archive_path, &engine)
        .map_err(|e| ForensicError::Container(format!("archive unpack failed: {e}")))?;

    let encrypted = result
        .warnings
        .iter()
        .any(|w| matches!(w, UnpackWarning::EncryptedArchive { .. }));
    if encrypted && result.total_files_extracted == 0 {
        return Err(ForensicError::UnsupportedImageFormat(
            "archive is encrypted — extract it externally with the password, then reopen the resulting folder in Strata"
                .into(),
        ));
    }

    log::info!(
        "Archive {:?} extracted to {:?}: {} files, {} bytes",
        archive_path,
        result.filesystem_root,
        result.total_files_extracted,
        result.total_bytes_extracted
    );
    Ok(result.filesystem_root)
}

pub fn detect_container_type(path: &Path) -> ContainerType {
    IngestRegistry::detect(path).container_type
}

#[cfg(test)]
mod sprint9_archive_ingestion_tests {
    //! Sprint-9 P3 — verify zip / tar archives flow through
    //! `EvidenceSource::open` end-to-end: detection → extraction →
    //! walkable VFS. Encryption returns a clear error rather than a
    //! silent empty extraction.

    use super::*;
    use std::io::Write;

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).expect("create zip");
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, payload) in entries {
            w.start_file::<_, ()>(*name, opts).expect("start");
            w.write_all(payload).expect("write");
        }
        w.finish().expect("finish");
    }

    fn collect_files(root: &Path, into: &mut Vec<PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    collect_files(&p, into);
                } else {
                    into.push(p);
                }
            }
        }
    }

    #[test]
    fn zip_extraction_produces_walkable_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let zip_path = dir.path().join("evidence.zip");
        write_zip(
            &zip_path,
            &[
                ("notes.txt", b"hello"),
                ("subdir/data.bin", &[0u8, 1, 2, 3]),
            ],
        );

        let src = EvidenceSource::open(&zip_path).expect("open zip");
        assert_eq!(src.container_type, ContainerType::ArchiveZip);
        let vfs = src.vfs.as_ref().expect("vfs");
        // FsVfs root points at the extracted layer — walking it must
        // surface the entries we packed.
        let root = vfs.root().clone();
        let mut walked = Vec::new();
        collect_files(&root, &mut walked);
        let names: Vec<String> = walked
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().any(|p| p.ends_with("notes.txt")),
            "expected notes.txt in extracted tree, got {names:?}"
        );
        assert!(
            names.iter().any(|p| p.ends_with("data.bin")),
            "expected subdir/data.bin in extracted tree, got {names:?}"
        );
    }

    #[test]
    fn tar_extraction_produces_walkable_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tar_path = dir.path().join("evidence.tar");
        let file = std::fs::File::create(&tar_path).expect("create tar");
        let mut builder = tar::Builder::new(file);
        let payload = b"tar body";
        let mut header = tar::Header::new_gnu();
        header.set_path("inside/file.txt").expect("set path");
        header.set_size(payload.len() as u64);
        header.set_cksum();
        builder
            .append(&header, std::io::Cursor::new(payload))
            .expect("append");
        builder.finish().expect("finish");

        let src = EvidenceSource::open(&tar_path).expect("open tar");
        assert_eq!(src.container_type, ContainerType::ArchiveTar);
        let root = src.vfs.as_ref().expect("vfs").root().clone();
        let mut walked = Vec::new();
        collect_files(&root, &mut walked);
        let found = walked
            .iter()
            .any(|p| p.file_name().map(|n| n == "file.txt").unwrap_or(false));
        assert!(found, "expected file.txt under extracted tar root {root:?}");
    }

    #[test]
    fn encrypted_zip_returns_clear_error() {
        use zip::unstable::write::FileOptionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let zip_path = dir.path().join("locked.zip");
        let file = std::fs::File::create(&zip_path).expect("create zip");
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"hunter2");
        w.start_file::<_, ()>("secret.txt", opts).expect("s");
        w.write_all(b"top secret").expect("w");
        w.finish().expect("f");

        let result = EvidenceSource::open(&zip_path);
        let err = match result {
            Ok(_) => panic!("encrypted zip must not silently produce empty VFS"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("encrypted"),
            "expected error to mention encryption, got {msg:?}"
        );
    }
}

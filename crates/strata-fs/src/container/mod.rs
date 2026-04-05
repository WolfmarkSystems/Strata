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
        println!(
            "DEBUG: EvidenceSource open: path={:?}, detected_type={:?}",
            path, container_type
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

pub fn detect_container_type(path: &Path) -> ContainerType {
    IngestRegistry::detect(path).container_type
}

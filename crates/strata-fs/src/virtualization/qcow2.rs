use crate::container::{EvidenceContainerRO, Qcow2Container};
use crate::errors::ForensicError;
use crate::virtualization::{detect_filesystem_in_buffer, VfsEntry, VirtualFileSystem, VolumeInfo};
use std::path::{Path, PathBuf};

pub struct Qcow2Vfs {
    root: PathBuf,
    container: Qcow2Container,
}

impl Qcow2Vfs {
    pub fn new(path: &Path) -> Result<Self, ForensicError> {
        let container = Qcow2Container::open(path)?;
        Ok(Self {
            root: path.to_path_buf(),
            container,
        })
    }

    fn normalize_virtual_path(path: &Path) -> String {
        let mut text = path.to_string_lossy().replace('\\', "/");
        if !text.starts_with('/') {
            text.insert(0, '/');
        }
        text.to_ascii_lowercase()
    }
}

impl VirtualFileSystem for Qcow2Vfs {
    fn root(&self) -> &PathBuf {
        &self.root
    }
    fn total_size(&self) -> u64 {
        self.container.size
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<VfsEntry>, ForensicError> {
        let norm = Self::normalize_virtual_path(path);
        if norm == "/" {
            return Ok(vec![VfsEntry {
                name: "vol0".to_string(),
                path: PathBuf::from("/vol0"),
                is_dir: true,
                size: self.container.size,
                modified: None,
            }]);
        }
        Ok(Vec::new())
    }

    fn open_file(&self, _path: &Path) -> Result<Vec<u8>, ForensicError> {
        Err(ForensicError::UnsupportedFilesystem)
    }

    fn file_metadata(&self, path: &Path) -> Result<VfsEntry, ForensicError> {
        let norm = Self::normalize_virtual_path(path);
        if norm == "/vol0" {
            return Ok(VfsEntry {
                name: "vol0".to_string(),
                path: PathBuf::from("/vol0"),
                is_dir: true,
                size: self.container.size,
                modified: None,
            });
        }
        Err(ForensicError::NotFound(norm))
    }

    fn get_volumes(&self) -> Vec<VolumeInfo> {
        let probe = self.read_volume_at(0, 4096).unwrap_or_default();
        let fs = detect_filesystem_in_buffer(&probe);
        vec![VolumeInfo {
            volume_index: 0,
            offset: 0,
            size: self.container.size,
            sector_size: 512,
            filesystem: fs,
            label: None,
            cluster_size: None,
            mft_offset: None,
            mft_record_size: None,
            serial_number: None,
        }]
    }

    fn read_volume_at(&self, offset: u64, size: usize) -> Result<Vec<u8>, ForensicError> {
        let mut buf = vec![0u8; size];
        self.container.read_into(offset, &mut buf)?;
        Ok(buf)
    }
}

use crate::container::{EvidenceContainerRO, IsoContainer};
use crate::errors::ForensicError;
use crate::virtualization::{FileSystemType, VfsEntry, VirtualFileSystem, VolumeInfo};
use std::path::{Path, PathBuf};

pub struct IsoVfs {
    root: PathBuf,
    container: IsoContainer,
}

impl IsoVfs {
    pub fn new(path: &Path) -> Result<Self, ForensicError> {
        let container = IsoContainer::open(path)?;
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

impl VirtualFileSystem for IsoVfs {
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

        if norm == "/vol0" {
            let entries = self
                .container
                .read_directory(self.container.root_lba, self.container.root_size)?;
            return Ok(entries
                .into_iter()
                .map(|e| VfsEntry {
                    name: e.name.clone(),
                    path: PathBuf::from(format!("/vol0/{}", e.name)),
                    is_dir: e.is_dir,
                    size: e.size as u64,
                    modified: None,
                })
                .collect());
        }

        Ok(Vec::new())
    }

    fn open_file(&self, path: &Path) -> Result<Vec<u8>, ForensicError> {
        let norm = Self::normalize_virtual_path(path);
        if !norm.starts_with("/vol0/") {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        let rel = norm.trim_start_matches("/vol0/");
        if rel.is_empty() || rel.contains('/') {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        let entries = self
            .container
            .read_directory(self.container.root_lba, self.container.root_size)?;
        if let Some(entry) = entries
            .into_iter()
            .find(|e| !e.is_dir && e.name.eq_ignore_ascii_case(rel))
        {
            return self.read_volume_at(entry.lba as u64 * 2048, entry.size as usize);
        }

        Err(ForensicError::NotFound(norm))
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
        if norm.starts_with("/vol0/") {
            let rel = norm.trim_start_matches("/vol0/");
            if !rel.is_empty() && !rel.contains('/') {
                let entries = self
                    .container
                    .read_directory(self.container.root_lba, self.container.root_size)?;
                if let Some(entry) = entries
                    .into_iter()
                    .find(|e| e.name.eq_ignore_ascii_case(rel))
                {
                    return Ok(VfsEntry {
                        name: entry.name.clone(),
                        path: PathBuf::from(format!("/vol0/{}", entry.name)),
                        is_dir: entry.is_dir,
                        size: entry.size as u64,
                        modified: None,
                    });
                }
            }
        }
        Err(ForensicError::NotFound(norm))
    }

    fn get_volumes(&self) -> Vec<VolumeInfo> {
        vec![VolumeInfo {
            volume_index: 0,
            offset: 0,
            size: self.container.size,
            sector_size: 2048,
            filesystem: FileSystemType::ISO9660,
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

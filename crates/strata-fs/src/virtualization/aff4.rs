use crate::container::{Aff4Container, EvidenceContainerRO};
use crate::errors::ForensicError;
use crate::virtualization::{FileSystemType, VfsEntry, VirtualFileSystem, VolumeInfo};
use std::path::{Path, PathBuf};

pub struct Aff4Vfs {
    root: PathBuf,
    container: Aff4Container,
}

impl Aff4Vfs {
    pub fn new(path: &Path) -> Result<Self, ForensicError> {
        let container = Aff4Container::open(path)?;
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
        while text.len() > 1 && text.ends_with('/') {
            text.pop();
        }
        text
    }

    fn to_vfs_entry(entry: crate::container::aff4::Aff4DirectoryEntry) -> VfsEntry {
        VfsEntry {
            path: PathBuf::from(entry.path),
            name: entry.name,
            is_dir: entry.is_dir,
            size: entry.size,
            modified: None,
        }
    }
}

impl VirtualFileSystem for Aff4Vfs {
    fn root(&self) -> &PathBuf {
        &self.root
    }

    fn total_size(&self) -> u64 {
        self.container.size
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<VfsEntry>, ForensicError> {
        let norm = Self::normalize_virtual_path(path);
        self.container
            .read_directory(&norm)
            .map(|entries| entries.into_iter().map(Self::to_vfs_entry).collect())
    }

    fn open_file(&self, path: &Path) -> Result<Vec<u8>, ForensicError> {
        let norm = Self::normalize_virtual_path(path);
        self.container.read_member(&norm)
    }

    fn file_metadata(&self, path: &Path) -> Result<VfsEntry, ForensicError> {
        let norm = Self::normalize_virtual_path(path);
        self.container
            .metadata_for_path(&norm)
            .map(Self::to_vfs_entry)
    }

    fn enumerate_volume(&self, _volume_index: usize) -> Result<Vec<VfsEntry>, ForensicError> {
        self.read_dir(Path::new("/"))
    }

    fn get_volumes(&self) -> Vec<VolumeInfo> {
        vec![VolumeInfo {
            volume_index: 0,
            offset: 0,
            size: self.container.size,
            sector_size: 512,
            filesystem: FileSystemType::Unknown,
            label: Some("AFF4".to_string()),
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

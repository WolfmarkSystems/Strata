use std::path::{Path, PathBuf};

use tracing::info;

use crate::container::{EvidenceContainerRO, VhdContainer, VhdxContainer};
use crate::errors::ForensicError;
use crate::virtualization::{FileSystemType, VfsEntry, VirtualFileSystem, VolumeInfo};

const ROOT_PATH: &str = "/";
const DEFAULT_VOLUME_PATH: &str = "/vol0";
const BOOT_SECTOR_PATH: &str = "/vol0/$boot";
const BOOT_SECTOR_SIZE: usize = 512;

enum MountedVhd {
    Vhd(VhdContainer),
    Vhdx(VhdxContainer),
}

impl MountedVhd {
    fn size(&self) -> u64 {
        match self {
            MountedVhd::Vhd(v) => v.size(),
            MountedVhd::Vhdx(v) => v.size(),
        }
    }

    fn sector_size(&self) -> u64 {
        match self {
            MountedVhd::Vhd(v) => v.sector_size(),
            MountedVhd::Vhdx(v) => v.sector_size(),
        }
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        match self {
            MountedVhd::Vhd(v) => v.read_into(offset, buf),
            MountedVhd::Vhdx(v) => v.read_into(offset, buf),
        }
    }
}

/// A Virtual File System wrapper around a VHD image container.
///
/// Month 2 starts by making VHD mounts honest and usable:
/// - a mounted VHD exposes a real `/vol0`
/// - callers can inspect the boot sector safely
/// - reads are clamped to the virtual disk size instead of panicking
///
/// Full partition/filesystem enumeration is a follow-on slice.
pub struct VhdVfs {
    root: PathBuf,
    container: MountedVhd,
}

impl VhdVfs {
    pub fn new(path: &Path) -> Result<Self, ForensicError> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        let container = if ext == "vhdx" {
            MountedVhd::Vhdx(VhdxContainer::open(path)?)
        } else if ext == "vhd" {
            MountedVhd::Vhd(VhdContainer::open(path)?)
        } else {
            match VhdContainer::open(path) {
                Ok(v) => MountedVhd::Vhd(v),
                Err(_) => MountedVhd::Vhdx(VhdxContainer::open(path)?),
            }
        };

        info!(
            "[VHD/VHDX] Mounted {:?} as {} bytes of virtual disk",
            path,
            container.size()
        );
        Ok(Self {
            root: path.to_path_buf(),
            container,
        })
    }

    fn normalize_virtual_path(path: &Path) -> String {
        let mut text = path.to_string_lossy().replace('\\', "/");
        if text.is_empty() {
            return ROOT_PATH.to_string();
        }
        if !text.starts_with('/') {
            text.insert(0, '/');
        }
        while text.contains("//") {
            text = text.replace("//", "/");
        }
        while text.len() > 1 && text.ends_with('/') {
            text.pop();
        }
        text.to_ascii_lowercase()
    }

    fn display_name(&self) -> String {
        self.root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "VHD Image".to_string())
    }

    fn volume_info(&self) -> VolumeInfo {
        let probe_size = self.total_size().min(64 * 1024) as usize;
        let filesystem = self
            .read_volume_at(0, probe_size)
            .ok()
            .map(|data| detect_filesystem_in_buffer(&data))
            .unwrap_or(FileSystemType::Unknown);

        VolumeInfo {
            volume_index: 0,
            offset: 0,
            size: self.total_size(),
            sector_size: self.container.sector_size(),
            filesystem,
            label: None,
            cluster_size: None,
            mft_offset: None,
            mft_record_size: None,
            serial_number: None,
        }
    }

    fn root_entry(&self) -> VfsEntry {
        VfsEntry {
            path: self.root.clone(),
            name: self.display_name(),
            is_dir: true,
            size: self.total_size(),
            modified: None,
        }
    }

    fn volume_entry(&self) -> VfsEntry {
        let volume = self.volume_info();
        VfsEntry {
            path: PathBuf::from(DEFAULT_VOLUME_PATH),
            name: format!(
                "{} Volume {} ({} GB)",
                volume.filesystem.as_str(),
                volume.volume_index,
                volume.size / 1_000_000_000
            ),
            is_dir: true,
            size: volume.size,
            modified: None,
        }
    }

    fn boot_sector_entry(&self) -> Option<VfsEntry> {
        if self.total_size() < BOOT_SECTOR_SIZE as u64 {
            return None;
        }

        Some(VfsEntry {
            path: PathBuf::from(BOOT_SECTOR_PATH),
            name: "Boot Sector (512 bytes)".to_string(),
            is_dir: false,
            size: BOOT_SECTOR_SIZE as u64,
            modified: None,
        })
    }
}

impl VirtualFileSystem for VhdVfs {
    fn root(&self) -> &PathBuf {
        &self.root
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<VfsEntry>, ForensicError> {
        match Self::normalize_virtual_path(path).as_str() {
            ROOT_PATH => Ok(vec![self.volume_entry()]),
            DEFAULT_VOLUME_PATH => Ok(self.boot_sector_entry().into_iter().collect()),
            _ => Ok(Vec::new()),
        }
    }

    fn open_file(&self, path: &Path) -> Result<Vec<u8>, ForensicError> {
        match Self::normalize_virtual_path(path).as_str() {
            BOOT_SECTOR_PATH => self.read_volume_at(0, BOOT_SECTOR_SIZE),
            _ => Err(ForensicError::UnsupportedFilesystem),
        }
    }

    fn file_metadata(&self, path: &Path) -> Result<VfsEntry, ForensicError> {
        match Self::normalize_virtual_path(path).as_str() {
            ROOT_PATH => Ok(self.root_entry()),
            DEFAULT_VOLUME_PATH => Ok(self.volume_entry()),
            BOOT_SECTOR_PATH => self
                .boot_sector_entry()
                .ok_or_else(|| ForensicError::OutOfRange(BOOT_SECTOR_PATH.to_string())),
            other => Err(ForensicError::OutOfRange(other.to_string())),
        }
    }

    fn total_size(&self) -> u64 {
        self.container.size()
    }

    fn get_volumes(&self) -> Vec<VolumeInfo> {
        vec![self.volume_info()]
    }

    fn enumerate_volume(&self, volume_index: usize) -> Result<Vec<VfsEntry>, ForensicError> {
        if volume_index == 0 {
            return self.read_dir(Path::new(DEFAULT_VOLUME_PATH));
        }
        Ok(Vec::new())
    }

    fn read_volume_at(&self, offset: u64, size: usize) -> Result<Vec<u8>, ForensicError> {
        if size == 0 {
            return Ok(Vec::new());
        }

        let disk_size = self.total_size();
        if offset >= disk_size {
            return Err(ForensicError::OutOfRange(format!(
                "vhd read offset {} beyond virtual disk size {}",
                offset, disk_size
            )));
        }

        let available = disk_size.saturating_sub(offset);
        let bounded_len = available.min(size as u64) as usize;
        let mut buf = vec![0u8; bounded_len];
        self.container.read_into(offset, &mut buf)?;
        Ok(buf)
    }
}

use crate::virtualization::detect_filesystem_in_buffer;

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    use tempfile::Builder;

    use super::{VhdVfs, BOOT_SECTOR_PATH, BOOT_SECTOR_SIZE, DEFAULT_VOLUME_PATH};
    use crate::virtualization::ImageFormat;
    use crate::virtualization::MountManager;
    use crate::virtualization::VirtualFileSystem;

    const DISK_SIZE: u64 = 4096;

    fn write_fixed_vhd(path: &Path, disk_data: &[u8]) {
        assert_eq!(disk_data.len() as u64, DISK_SIZE);

        let mut footer = [0u8; 512];
        footer[0..8].copy_from_slice(b"conectix");
        footer[8..12].copy_from_slice(&2u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        footer[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        footer[40..48].copy_from_slice(&DISK_SIZE.to_be_bytes());
        footer[48..56].copy_from_slice(&DISK_SIZE.to_be_bytes());
        footer[60..64].copy_from_slice(&2u32.to_be_bytes());

        let mut file = File::create(path).unwrap();
        file.write_all(disk_data).unwrap();
        file.write_all(&footer).unwrap();
        file.flush().unwrap();
    }

    fn create_fixed_vhd() -> tempfile::NamedTempFile {
        let temp = Builder::new().suffix(".vhd").tempfile().unwrap();
        let mut disk_data = vec![0u8; DISK_SIZE as usize];
        disk_data[0] = 0xEB;
        disk_data[1] = 0x52;
        disk_data[2] = 0x90;
        disk_data[3..11].copy_from_slice(b"NTFS    ");
        disk_data[11..13].copy_from_slice(&512u16.to_le_bytes());
        disk_data[13] = 0x01;
        write_fixed_vhd(temp.path(), &disk_data);
        temp
    }

    #[test]
    fn vhd_vfs_exposes_root_volume_and_boot_sector() {
        let temp = create_fixed_vhd();
        let vfs = VhdVfs::new(temp.path()).unwrap();

        let root_entries = vfs.read_dir(Path::new("/")).unwrap();
        assert_eq!(root_entries.len(), 1);
        assert_eq!(root_entries[0].path, Path::new(DEFAULT_VOLUME_PATH));

        let volume_entries = vfs.read_dir(Path::new(DEFAULT_VOLUME_PATH)).unwrap();
        assert_eq!(volume_entries.len(), 1);
        assert_eq!(volume_entries[0].path, Path::new(BOOT_SECTOR_PATH));
        assert_eq!(volume_entries[0].size, BOOT_SECTOR_SIZE as u64);

        let volume_meta = vfs.file_metadata(Path::new(DEFAULT_VOLUME_PATH)).unwrap();
        assert!(volume_meta.is_dir);
        assert_eq!(volume_meta.size, DISK_SIZE);

        let boot = vfs.open_file(Path::new(BOOT_SECTOR_PATH)).unwrap();
        assert_eq!(boot.len(), BOOT_SECTOR_SIZE);
        assert_eq!(&boot[3..11], b"NTFS    ");
    }

    #[test]
    fn vhd_vfs_clamps_tail_reads() {
        let temp = create_fixed_vhd();
        let vfs = VhdVfs::new(temp.path()).unwrap();

        let tail = vfs.read_volume_at(DISK_SIZE - 16, 64).unwrap();
        assert_eq!(tail.len(), 16);

        let past_eof = vfs.read_volume_at(DISK_SIZE, 1);
        assert!(past_eof.is_err());
    }

    #[test]
    fn mount_manager_uses_vhd_vfs_for_vhd_images() {
        let temp = create_fixed_vhd();
        let mounted = MountManager::mount(temp.path()).unwrap();

        assert_eq!(mounted.format, ImageFormat::VHD);
        assert_eq!(mounted.total_size, DISK_SIZE);
        assert_eq!(mounted.volumes.len(), 1);
        assert_eq!(mounted.volumes[0].filesystem.as_str(), "NTFS");
        assert_eq!(mounted.vfs.read_dir(Path::new("/")).unwrap().len(), 1);
    }
}

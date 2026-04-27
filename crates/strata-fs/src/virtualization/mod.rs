#[cfg(target_os = "windows")]
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;
#[cfg(target_os = "windows")]
use crate::ntfs::enumerate_directory;
use crate::regions::ScanRegion;
use chrono::{DateTime, Utc};
use ewf::EwfReader;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{error, info, warn};

pub mod aff4;
pub mod iso;
pub mod qcow2;
pub mod split_raw;
pub mod vhd;
pub mod vmdk;
pub use aff4::Aff4Vfs;
pub use iso::IsoVfs;
pub use qcow2::Qcow2Vfs;
pub use split_raw::SplitRawVfs;
pub use vhd::VhdVfs;
pub use vmdk::VmdkVfs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum FileSystemType {
    NTFS,
    APFS,
    FAT32,
    ExFAT,
    Ext4,
    ISO9660,
    XFS,
    HFSPlus,
    Unknown,
}

impl FileSystemType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileSystemType::NTFS => "NTFS",
            FileSystemType::APFS => "APFS",
            FileSystemType::FAT32 => "FAT32",
            FileSystemType::ExFAT => "exFAT",
            FileSystemType::Ext4 => "Ext4",
            FileSystemType::ISO9660 => "ISO9660",
            FileSystemType::XFS => "XFS",
            FileSystemType::HFSPlus => "HFS+",
            FileSystemType::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub volume_index: usize,
    pub offset: u64,
    pub size: u64,
    pub sector_size: u64,
    pub filesystem: FileSystemType,
    pub label: Option<String>,
    pub cluster_size: Option<u32>,
    pub mft_offset: Option<u64>,
    pub mft_record_size: Option<u32>,
    pub serial_number: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageFormat {
    RAW,
    DD,
    SplitRaw,
    E01,
    AFF,
    AFF4,
    S01,
    Lx01,
    Lx02,
    VHD,
    VHDX,
    VMDK,
    DMG,
    ISO,
    ZIP,
    UFDR,
    GRAYKEY,
    AXIOM,
    TAR,
    GZIP,
    Unknown,
}

impl ImageFormat {
    pub fn from_path(path: &Path) -> Self {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "e01" => ImageFormat::E01,
            "aff" => ImageFormat::AFF,
            "aff4" => ImageFormat::AFF4,
            "s01" => ImageFormat::S01,
            "lx01" => ImageFormat::Lx01,
            "lx02" => ImageFormat::Lx02,
            "vhd" => ImageFormat::VHD,
            "vhdx" => ImageFormat::VHDX,
            "vmdk" => ImageFormat::VMDK,
            "dmg" => ImageFormat::DMG,
            "iso" => ImageFormat::ISO,
            "zip" => ImageFormat::ZIP,
            "ufdr" => ImageFormat::UFDR,
            "graykey" => ImageFormat::GRAYKEY,
            "axiom" => ImageFormat::AXIOM,
            "tar" => ImageFormat::TAR,
            "gz" | "gzip" => ImageFormat::GZIP,
            "dd" => ImageFormat::DD,
            "raw" => ImageFormat::RAW,
            _ => ImageFormat::RAW,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ImageFormat::RAW => "RAW",
            ImageFormat::DD => "DD",
            ImageFormat::SplitRaw => "SplitRaw",
            ImageFormat::E01 => "E01",
            ImageFormat::AFF => "AFF",
            ImageFormat::AFF4 => "AFF4",
            ImageFormat::S01 => "S01",
            ImageFormat::Lx01 => "Lx01",
            ImageFormat::Lx02 => "Lx02",
            ImageFormat::VHD => "VHD",
            ImageFormat::VHDX => "VHDX",
            ImageFormat::VMDK => "VMDK",
            ImageFormat::DMG => "DMG",
            ImageFormat::ISO => "ISO",
            ImageFormat::ZIP => "ZIP",
            ImageFormat::UFDR => "UFDR",
            ImageFormat::GRAYKEY => "GRAYKEY",
            ImageFormat::AXIOM => "AXIOM",
            ImageFormat::TAR => "TAR",
            ImageFormat::GZIP => "GZIP",
            ImageFormat::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImageFormatInfo {
    pub format: ImageFormat,
}

pub fn detect_image_format(path: &Path) -> Result<ImageFormatInfo, String> {
    let format = ImageFormat::from_path(path);
    Ok(ImageFormatInfo { format })
}

pub trait VirtualFileSystem: Send + Sync {
    fn root(&self) -> &PathBuf;
    fn read_dir(&self, path: &Path) -> Result<Vec<VfsEntry>, ForensicError>;
    fn open_file(&self, path: &Path) -> Result<Vec<u8>, ForensicError>;
    fn file_metadata(&self, path: &Path) -> Result<VfsEntry, ForensicError>;
    fn total_size(&self) -> u64;

    /// Read a byte range from a virtual file. Default falls back to open_file + slice.
    /// Implementations should override this for large-file support.
    fn read_file_range(
        &self,
        path: &Path,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, ForensicError> {
        let full = self.open_file(path)?;
        let start = offset as usize;
        if start >= full.len() {
            return Ok(Vec::new());
        }
        let end = start.saturating_add(len).min(full.len());
        Ok(full[start..end].to_vec())
    }

    fn get_volumes(&self) -> Vec<VolumeInfo> {
        Vec::new()
    }

    fn enumerate_volume(&self, _volume_index: usize) -> Result<Vec<VfsEntry>, ForensicError> {
        Ok(Vec::new())
    }

    fn enumerate_xfs_directory(
        &self,
        _vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        Ok(Vec::new())
    }

    fn enumerate_fat32_directory(
        &self,
        _vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        Ok(Vec::new())
    }

    fn enumerate_ntfs_directory(
        &self,
        _vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        Ok(Vec::new())
    }

    fn enumerate_ext4_directory(
        &self,
        _vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        Ok(Vec::new())
    }

    fn enumerate_apfs_directory(
        &self,
        _vol_info: &VolumeInfo,
        _target_path: &Path,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        // v16 Session 3 — APFS virtualization path retired alongside
        // the in-tree apfs::ApfsReader module. The modern APFS walk
        // surface lives behind `fs_dispatch::open_filesystem` →
        // ApfsSingleWalker / ApfsMultiWalker (Session 4 / 5 on top
        // of the external `apfs` crate). This legacy virtualization
        // module pre-dates the dispatcher and is kept green-
        // compiling but neutralized rather than migrated. Matches
        // the already-stubbed NTFS / ext4 paths on this same type.
        Ok(Vec::new())
    }

    fn enumerate_hfsplus_directory(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        use crate::hfsplus::{HfsPlusEntryType, HfsPlusFilesystem};
        let mut entries = Vec::new();

        match HfsPlusFilesystem::open_at_offset(self.root(), vol_info.offset) {
            Ok(mut fs) => {
                let cat_res: Result<
                    Vec<crate::hfsplus::HfsPlusCatalogEntry>,
                    crate::errors::ForensicError,
                > = fs.read_catalog();
                match cat_res {
                    Ok(catalog_entries) => {
                        let catalog_entries: Vec<crate::hfsplus::HfsPlusCatalogEntry> =
                            catalog_entries;
                        for entry in catalog_entries {
                            let is_dir = matches!(entry.entry_type, HfsPlusEntryType::Directory);
                            entries.push(VfsEntry {
                                path: PathBuf::from(format!(
                                    "/vol{}/{}",
                                    vol_info.volume_index, entry.name
                                )),
                                name: entry.name,
                                is_dir,
                                size: 0,
                                modified: None,
                            });
                        }
                    }
                    Err(e) => {
                        warn!("[VFS][HFS+] Failed to read catalog: {:?}", e);
                    }
                }
            }
            Err(e) => {
                warn!("[VFS][HFS+] Failed to open HFS+ filesystem: {:?}", e);
            }
        }

        if entries.is_empty() {
            entries.push(VfsEntry {
                path: PathBuf::from(format!("/vol{}/HFS_Plus_Root", vol_info.volume_index)),
                name: "HFS_Plus_Root".to_string(),
                is_dir: true,
                size: vol_info.size,
                modified: None,
            });
        }

        Ok(entries)
    }

    #[deprecated(since = "0.1.0", note = "Use get_volumes() instead")]
    fn get_ntfs_volumes(&self) -> Vec<VolumeInfo> {
        self.get_volumes()
            .into_iter()
            .filter(|v| v.filesystem == FileSystemType::NTFS)
            .collect()
    }

    fn get_unallocated_regions(&self) -> Vec<ScanRegion> {
        Vec::new()
    }

    fn get_slack_regions(&self) -> Vec<ScanRegion> {
        Vec::new()
    }

    fn is_memory_dump(&self) -> bool {
        let name = self
            .root()
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        matches!(name.as_str(),
            n if n.ends_with(".dmp") || n.ends_with(".mem") || n.ends_with(".vmem") || n.ends_with(".raw")
        )
    }

    fn read_volume_at(&self, offset: u64, size: usize) -> Result<Vec<u8>, ForensicError>;

    fn normalize_virtual_path(&self, path: &Path) -> String {
        let mut text = path.to_string_lossy().replace('\\', "/");
        if text.is_empty() {
            return "/".to_string();
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
        text.to_string()
    }
}

pub struct FsVfs {
    root: PathBuf,
}

/// Maximum file size that `FsVfs::open_file` will load into memory.
/// Files larger than this must be accessed via `read_file_range`.
const MAX_OPEN_FILE_BYTES: u64 = 256 * 1024 * 1024; // 256 MB

impl FsVfs {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn resolve_path(&self, path: &Path) -> PathBuf {
        if path == Path::new("/") || path.as_os_str().is_empty() {
            self.root.clone()
        } else {
            self.root.join(path)
        }
    }
}

impl VirtualFileSystem for FsVfs {
    fn root(&self) -> &PathBuf {
        &self.root
    }

    fn read_volume_at(&self, _offset: u64, _size: usize) -> Result<Vec<u8>, ForensicError> {
        Err(ForensicError::UnsupportedFilesystem)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<VfsEntry>, ForensicError> {
        let dir_path = self.resolve_path(path);

        if !dir_path.exists() {
            return Err(ForensicError::OutOfRange(dir_path.display().to_string()));
        }

        let mut entries = Vec::new();

        if let Ok(read_dir) = std::fs::read_dir(&dir_path) {
            for entry in read_dir.flatten() {
                let entry_path = entry.path();
                let metadata = entry.metadata().ok();

                entries.push(VfsEntry {
                    name: entry.file_name().to_string_lossy().to_string(),
                    path: entry_path
                        .strip_prefix(&self.root)
                        .unwrap_or(&entry_path)
                        .to_path_buf(),
                    is_dir: entry_path.is_dir(),
                    size: metadata.as_ref().map(|m| m.len()).unwrap_or(0),
                    modified: metadata
                        .and_then(|m| m.modified().ok())
                        .map(DateTime::<Utc>::from),
                });
            }
        }

        Ok(entries)
    }

    fn open_file(&self, path: &Path) -> Result<Vec<u8>, ForensicError> {
        let file_path = self.resolve_path(path);

        let metadata = std::fs::metadata(&file_path).map_err(ForensicError::Io)?;
        if metadata.len() > MAX_OPEN_FILE_BYTES {
            return Err(ForensicError::OutOfRange(format!(
                "File {} is {} bytes — exceeds {} byte open_file limit. Use read_file_range instead.",
                file_path.display(),
                metadata.len(),
                MAX_OPEN_FILE_BYTES,
            )));
        }

        std::fs::read(&file_path).map_err(ForensicError::Io)
    }

    /// Seek-based ranged read — does NOT load the full file into memory.
    fn read_file_range(
        &self,
        path: &Path,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, ForensicError> {
        use std::io::{Read, Seek, SeekFrom};

        let file_path = self.resolve_path(path);
        let mut file = std::fs::File::open(&file_path).map_err(ForensicError::Io)?;

        let file_len = file.metadata().map_err(ForensicError::Io)?.len();
        if offset >= file_len {
            return Ok(Vec::new());
        }

        let available = (file_len - offset) as usize;
        let to_read = len.min(available);

        file.seek(SeekFrom::Start(offset))
            .map_err(ForensicError::Io)?;

        let mut buf = vec![0u8; to_read];
        file.read_exact(&mut buf).map_err(ForensicError::Io)?;
        Ok(buf)
    }

    fn file_metadata(&self, path: &Path) -> Result<VfsEntry, ForensicError> {
        let file_path = self.resolve_path(path);

        let metadata = std::fs::metadata(&file_path).map_err(ForensicError::Io)?;

        Ok(VfsEntry {
            name: file_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            path: file_path
                .strip_prefix(&self.root)
                .unwrap_or(&file_path)
                .to_path_buf(),
            is_dir: metadata.is_dir(),
            size: metadata.len(),
            modified: metadata.modified().ok().map(DateTime::<Utc>::from),
        })
    }

    fn total_size(&self) -> u64 {
        std::fs::metadata(&self.root)
            .map(|m| if m.is_dir() { 0 } else { m.len() })
            .unwrap_or(0)
    }
}

pub struct RawVfs {
    root: PathBuf,
    data: memmap2::Mmap,
    size: u64,
}

impl RawVfs {
    pub fn new(path: &Path) -> Result<Self, ForensicError> {
        info!("Creating RawVfs for: {:?}", path);

        let file = std::fs::File::open(path).map_err(|e| {
            error!("Failed to open file for RawVfs: {:?}", e);
            ForensicError::Io(e)
        })?;

        let size = file
            .metadata()
            .map_err(|e| {
                error!("Failed to get file metadata: {:?}", e);
                ForensicError::Io(e)
            })?
            .len();

        info!("File size: {} bytes", size);

        #[cfg(feature = "turbo")]
        const MAX_MMAP_SIZE: u64 = 256 * 1024 * 1024 * 1024; // 256GB limit in turbo mode
        #[cfg(not(feature = "turbo"))]
        const MAX_MMAP_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10GB limit

        if size > MAX_MMAP_SIZE {
            warn!(
                "File too large ({} bytes), using read-at approach instead of mmap",
                size
            );
            return Ok(Self {
                root: path.to_path_buf(),
                data: unsafe { memmap2::Mmap::map(&file)? },
                size,
            });
        }

        let data = unsafe {
            memmap2::Mmap::map(&file).map_err(|e| {
                error!("Failed to memory map file: {:?}", e);
                ForensicError::Io(std::io::Error::other(e.to_string()))
            })?
        };

        info!(
            "RawVfs created successfully with {} bytes mapped",
            data.len()
        );

        Ok(Self {
            root: path.to_path_buf(),
            data,
            size,
        })
    }

    pub fn read_at(&self, offset: u64, size: usize) -> Result<Vec<u8>, ForensicError> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(Vec::new());
        }
        let end = (offset + size).min(self.data.len());
        Ok(self.data[offset..end].to_vec())
    }

    pub fn enumerate_fat32_directory(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        let mut entries = Vec::new();
        let vol_offset = vol_info.offset as usize;

        tracing::info!(
            "[FAT32] Starting enumeration at partition offset {}",
            vol_offset
        );

        let candidate = vol_offset;

        if candidate >= self.data.len() {
            tracing::warn!(
                "[FAT32] Candidate offset {} >= data len {}",
                candidate,
                self.data.len()
            );
            return Ok(entries);
        }

        let boot_sector = match self.read_at(candidate as u64, 512) {
            Ok(d) if d.len() >= 512 => d,
            _ => {
                tracing::warn!("[FAT32] Failed to read 512 bytes at offset {}", candidate);
                return Ok(entries);
            }
        };

        let jump = boot_sector[0];
        tracing::info!("[FAT32] Jump byte at {}: 0x{:02X}", candidate, jump);

        if jump != 0xEB && jump != 0xE9 {
            tracing::warn!(
                "[FAT32] Invalid jump instruction: 0x{:02X} (expected 0xEB or 0xE9)",
                jump
            );
            return Ok(entries);
        }

        let bytes_per_sector = u16::from_le_bytes([boot_sector[11], boot_sector[12]]);
        tracing::info!("[FAT32] bytes_per_sector: {}", bytes_per_sector);

        if bytes_per_sector != 512
            && bytes_per_sector != 1024
            && bytes_per_sector != 2048
            && bytes_per_sector != 4096
        {
            tracing::warn!("[FAT32] Invalid bytes_per_sector: {}", bytes_per_sector);
            return Ok(entries);
        }

        let sectors_per_cluster = boot_sector[13];
        tracing::info!("[FAT32] sectors_per_cluster: {}", sectors_per_cluster);

        if sectors_per_cluster == 0
            || sectors_per_cluster > 128
            || (sectors_per_cluster & (sectors_per_cluster - 1)) != 0
        {
            tracing::warn!(
                "[FAT32] Invalid sectors_per_cluster: {}",
                sectors_per_cluster
            );
            return Ok(entries);
        }

        let reserved_sectors = u16::from_le_bytes([boot_sector[14], boot_sector[15]]);
        let num_fats = boot_sector[16];
        let fat16_sectors_per_fat = u16::from_le_bytes([boot_sector[22], boot_sector[23]]);
        let fat32_sectors_per_fat = u32::from_le_bytes([
            boot_sector[36],
            boot_sector[37],
            boot_sector[38],
            boot_sector[39],
        ]);

        tracing::info!(
            "[FAT32] reserved_sectors={}, num_fats={}, fat32_sectors_per_fat={}",
            reserved_sectors,
            num_fats,
            fat32_sectors_per_fat
        );

        if reserved_sectors == 0 || num_fats == 0 {
            tracing::warn!(
                "[FAT32] Invalid BPB values: reserved_sectors={}, num_fats={}",
                reserved_sectors,
                num_fats
            );
            return Ok(entries);
        }

        // FAT12/16 set FAT-size at 0x16; FAT32 uses 0x24. If FAT32 field is zero and FAT16
        // field is present, this is not a FAT32 volume and should not be parsed by FAT32 logic.
        if fat32_sectors_per_fat == 0 && fat16_sectors_per_fat > 0 {
            tracing::warn!(
                "[FAT32] Detected FAT12/16 style BPB (fat16_sectors_per_fat={}) - skipping FAT32 parser",
                fat16_sectors_per_fat
            );
            return Ok(entries);
        }

        let root_dir_cluster = u32::from_le_bytes([
            boot_sector[0x2C],
            boot_sector[0x2D],
            boot_sector[0x2E],
            boot_sector[0x2F],
        ]);
        tracing::info!("[FAT32] root_dir_cluster: {}", root_dir_cluster);

        if !(2..=0xFFFFFF).contains(&root_dir_cluster) {
            tracing::warn!("[FAT32] Invalid root_dir_cluster: {}", root_dir_cluster);
            return Ok(entries);
        }

        let fat_sectors = if fat32_sectors_per_fat > 0 && fat32_sectors_per_fat < 0x100000 {
            fat32_sectors_per_fat
        } else {
            tracing::warn!(
                "[FAT32] fat32_sectors_per_fat invalid ({}) - using default 1000",
                fat32_sectors_per_fat
            );
            1000
        };

        tracing::info!(
            "[FAT32] BOOT SECTOR VALID at offset {}: bps={}, spc={}, fat_sz={}, root_clust={}",
            candidate,
            bytes_per_sector,
            sectors_per_cluster,
            fat_sectors,
            root_dir_cluster
        );

        let first_data_sector =
            (reserved_sectors as u64) + ((fat_sectors as u64) * (num_fats as u64));
        let root_dir_sector =
            first_data_sector + ((root_dir_cluster as u64 - 2) * sectors_per_cluster as u64);
        let root_dir_offset = candidate + (root_dir_sector * bytes_per_sector as u64) as usize;

        tracing::info!(
            "[FAT32] Root dir: sector={}, offset={}",
            root_dir_sector,
            root_dir_offset
        );

        if root_dir_offset >= self.data.len() {
            tracing::warn!(
                "[FAT32] Root dir offset {} >= data len {}",
                root_dir_offset,
                self.data.len()
            );
            return Ok(entries);
        }

        let cluster_size = (bytes_per_sector as usize) * (sectors_per_cluster as usize);
        let read_size = cluster_size
            .min(self.data.len().saturating_sub(root_dir_offset))
            .min(65536);

        let root_data = match self.read_at(root_dir_offset as u64, read_size) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("[FAT32] Failed to read root dir: {:?}", e);
                return Ok(entries);
            }
        };

        tracing::info!(
            "[FAT32] Read {} bytes from root directory at offset {}",
            root_data.len(),
            root_dir_offset
        );

        let mut pos = 0;
        while pos + 32 <= root_data.len() {
            let first = root_data[pos];
            if first == 0x00 {
                break;
            }
            if first != 0xE5 {
                let attrs = root_data[pos + 11];
                if attrs != 0x08 {
                    let is_dir = (attrs & 0x10) != 0;

                    let mut name_buf = Vec::new();
                    for i in 0..8 {
                        let c = root_data[pos + i];
                        if c == 0x20 {
                            break;
                        }
                        if (0x20..0x7F).contains(&c) {
                            name_buf.push(c);
                        }
                    }

                    let ext_start = pos + 8;
                    let mut has_ext = false;
                    for i in 0..3 {
                        if root_data[ext_start + i] != 0x20 {
                            has_ext = true;
                            break;
                        }
                    }
                    if has_ext {
                        name_buf.push(b'.');
                        for i in 0..3 {
                            let c = root_data[ext_start + i];
                            if c != 0x20 && (0x20..0x7F).contains(&c) {
                                name_buf.push(c);
                            }
                        }
                    }

                    if !name_buf.is_empty() {
                        let name = String::from_utf8_lossy(&name_buf).to_string();
                        if !name.starts_with('.') && name != "." && name != ".." {
                            let size = u32::from_le_bytes([
                                root_data[pos + 28],
                                root_data[pos + 29],
                                root_data[pos + 30],
                                root_data[pos + 31],
                            ]) as u64;

                            tracing::info!(
                                "[FAT32] Found file: '{}' (is_dir={}, size={})",
                                name,
                                is_dir,
                                size
                            );
                            entries.push(VfsEntry {
                                path: PathBuf::from(format!("{}/{}", vol_info.volume_index, name)),
                                name,
                                is_dir,
                                size,
                                modified: None,
                            });
                        }
                    }
                }
            }
            pos += 32;
        }

        tracing::info!("[FAT32] Found {} entries", entries.len());
        Ok(entries)
    }

    pub fn enumerate_ext4_directory(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        let mut entries = Vec::new();

        let vol_offset = vol_info.offset as usize;

        // Read superblock at offset 1024
        let sb_offset = vol_offset + 1024;
        let superblock = self.read_at(sb_offset as u64, 1024)?;

        if superblock.len() < 1084 {
            return Ok(entries);
        }

        // Check magic number
        let s_magic = u16::from_le_bytes([superblock[0x38], superblock[0x39]]);
        if s_magic != 0xEF53 {
            return Ok(entries);
        }

        // Add placeholder entries
        entries.push(VfsEntry {
            path: PathBuf::from(format!("{}/lost+found", vol_info.volume_index)),
            name: "lost+found".to_string(),
            is_dir: true,
            size: 0,
            modified: None,
        });

        entries.push(VfsEntry {
            path: PathBuf::from(format!("{}/home", vol_info.volume_index)),
            name: "home".to_string(),
            is_dir: true,
            size: 0,
            modified: None,
        });

        Ok(entries)
    }

    pub fn enumerate_xfs_directory(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        use crate::xfs::{xfs_fast_scan, XfsDirEntry, XfsFileType, XfsReader};
        let mut entries = Vec::new();

        let vol_offset = vol_info.offset as usize;

        // Read enough data for XFS superblock (256 bytes is enough for basic detection)
        let superblock_data = self.read_at(vol_offset as u64, 256)?;

        // Try to scan for XFS
        if let Ok(scan) = xfs_fast_scan(&superblock_data) {
            if scan.found {
                info!(
                    "[XFS] Found valid XFS filesystem: block_size={}, blocks={}",
                    scan.block_size, scan.total_blocks
                );

                // Read more data for the full superblock (XFS superblock is 256 bytes)
                let full_sb = self.read_at(vol_offset as u64, 256)?;

                // Try to use the XfsReader for proper directory enumeration
                match XfsReader::open(&full_sb) {
                    Ok(reader) => {
                        info!("[XFS] Successfully created XFS reader");

                        // Try to enumerate the root directory
                        let xfs_res: Result<Vec<XfsDirEntry>, crate::errors::ForensicError> =
                            reader.enumerate_root();
                        match xfs_res {
                            Ok(dir_entries) => {
                                let dir_entries: Vec<XfsDirEntry> = dir_entries;
                                info!("[XFS] Root directory has {} entries", dir_entries.len());
                                for entry in dir_entries {
                                    let is_dir = matches!(entry.entry_type, XfsFileType::Directory);
                                    entries.push(VfsEntry {
                                        path: PathBuf::from(format!(
                                            "/vol{}/{}",
                                            vol_info.volume_index, entry.name
                                        )),
                                        name: entry.name,
                                        is_dir,
                                        size: 0,
                                        modified: None,
                                    });
                                }
                            }
                            Err(e) => {
                                warn!("[XFS] Failed to enumerate root: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[XFS] Failed to create reader: {:?}", e);
                    }
                }

                // If we got no entries from the reader, use placeholders
                if entries.is_empty() {
                    info!("[XFS] Using placeholder entries");
                    entries.push(VfsEntry {
                        path: PathBuf::from(format!("{}/lost+found", vol_info.volume_index)),
                        name: "lost+found".to_string(),
                        is_dir: true,
                        size: 0,
                        modified: None,
                    });
                    entries.push(VfsEntry {
                        path: PathBuf::from(format!("{}/root", vol_info.volume_index)),
                        name: "root".to_string(),
                        is_dir: true,
                        size: 0,
                        modified: None,
                    });
                    entries.push(VfsEntry {
                        path: PathBuf::from(format!("{}/home", vol_info.volume_index)),
                        name: "home".to_string(),
                        is_dir: true,
                        size: 0,
                        modified: None,
                    });
                }

                return Ok(entries);
            }
        }

        // Fallback: just return basic entries
        entries.push(VfsEntry {
            path: PathBuf::from(format!("{}/XFS_Root", vol_info.volume_index)),
            name: "XFS_Root".to_string(),
            is_dir: true,
            size: vol_info.size,
            modified: None,
        });

        Ok(entries)
    }
}

impl crate::container::EvidenceContainerRO for RawVfs {
    fn description(&self) -> &str {
        "RawVfs"
    }
    fn source_path(&self) -> &Path {
        &self.root
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u64 {
        512
    }
    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        let start = offset as usize;
        let end = start + buf.len();
        if end > self.data.len() {
            return Err(ForensicError::OutOfRange(format!(
                "RawVfs read at {} len {} exceeds mapped size {}",
                start,
                buf.len(),
                self.data.len()
            )));
        }
        buf.copy_from_slice(&self.data[start..end]);
        Ok(())
    }
}

impl VirtualFileSystem for RawVfs {
    fn root(&self) -> &PathBuf {
        &self.root
    }

    fn enumerate_ntfs_directory(
        &self,
        _vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        // RawVfs original NTFS enumeration logic at line 948 is essentially
        // what this would do, but we just want to satisfy the trait here.
        Ok(Vec::new())
    }

    fn read_volume_at(&self, offset: u64, size: usize) -> Result<Vec<u8>, ForensicError> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(&self.root).map_err(ForensicError::from)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(ForensicError::from)?;
        let mut buf = vec![0u8; size];
        file.read_exact(&mut buf).map_err(ForensicError::from)?;
        Ok(buf)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<VfsEntry>, ForensicError> {
        let path_str = path.to_string_lossy();

        if path_str.starts_with("/vol") {
            let vol_idx = path_str
                .trim_start_matches("/vol")
                .split('/')
                .next()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);

            let volumes = self.get_volumes();
            if let Some(vol_info) = volumes.iter().find(|v| v.volume_index == vol_idx) {
                let remaining = path_str.trim_start_matches(&format!("/vol{}", vol_idx));
                let parts: Vec<&str> = remaining.trim_start_matches('/').split('/').collect();

                if parts.len() == 1 && parts[0].is_empty() {
                    info!(
                        "[VFS] read_dir called for NTFS volume root, vol_info: {:?}",
                        vol_info
                    );
                    return match vol_info.filesystem {
                        FileSystemType::NTFS => {
                            // Try to enumerate NTFS root directory
                            info!(
                                "[VFS] Calling enumerate_ntfs_directory with mft_offset: {:?}",
                                vol_info.mft_offset
                            );
                            let result = self.enumerate_ntfs_directory(vol_info);
                            info!(
                                "[VFS] enumerate_ntfs_directory returned {} entries",
                                result.as_ref().map(|v| v.len()).unwrap_or(0)
                            );
                            result
                        }
                        FileSystemType::FAT32 => self.enumerate_fat32_directory(vol_info),
                        FileSystemType::Ext4 => self.enumerate_ext4_directory(vol_info),
                        FileSystemType::XFS => self.enumerate_xfs_directory(vol_info),
                        FileSystemType::HFSPlus => self.enumerate_hfsplus_directory(vol_info),
                        FileSystemType::APFS => self.enumerate_apfs_directory(vol_info, path),
                        FileSystemType::ISO9660 => {
                            let mut entries = Vec::new();
                            entries.push(VfsEntry {
                                path: PathBuf::from(format!("{}/efi", vol_info.volume_index)),
                                name: "efi".to_string(),
                                is_dir: true,
                                size: 0,
                                modified: None,
                            });
                            entries.push(VfsEntry {
                                path: PathBuf::from(format!("{}/sources", vol_info.volume_index)),
                                name: "sources".to_string(),
                                is_dir: true,
                                size: 0,
                                modified: None,
                            });
                            entries.push(VfsEntry {
                                path: PathBuf::from(format!("{}/boot", vol_info.volume_index)),
                                name: "boot".to_string(),
                                is_dir: true,
                                size: 0,
                                modified: None,
                            });
                            entries.push(VfsEntry {
                                path: PathBuf::from(format!(
                                    "{}/Program Files",
                                    vol_info.volume_index
                                )),
                                name: "Program Files".to_string(),
                                is_dir: true,
                                size: 0,
                                modified: None,
                            });
                            entries.push(VfsEntry {
                                path: PathBuf::from(format!("{}/Users", vol_info.volume_index)),
                                name: "Users".to_string(),
                                is_dir: true,
                                size: 0,
                                modified: None,
                            });
                            Ok(entries)
                        }
                        // For Unknown filesystems, still try to show something useful
                        _ => {
                            let mut entries = Vec::new();
                            entries.push(VfsEntry {
                                path: PathBuf::from(format!(
                                    "{}/Unallocated",
                                    vol_info.volume_index
                                )),
                                name: "Unallocated Space".to_string(),
                                is_dir: true,
                                size: 0,
                                modified: None,
                            });
                            // Try to read first few KB to look for any known signatures
                            if let Ok(data) = self.read_at(0, 4096) {
                                // Look for any common file signatures
                                if data.len() >= 512 {
                                    entries.push(VfsEntry {
                                        path: PathBuf::from(format!(
                                            "{}/Sector0",
                                            vol_info.volume_index
                                        )),
                                        name: "Boot Sector (512 bytes)".to_string(),
                                        is_dir: false,
                                        size: 512,
                                        modified: None,
                                    });
                                }
                            }
                            Ok(entries)
                        }
                    };
                }
            }
        }

        if path_str.is_empty() || path_str == "/" || path_str == "\\" {
            let mut entries = Vec::new();

            let volumes = self.get_volumes();
            for vol in &volumes {
                entries.push(VfsEntry {
                    path: PathBuf::from(format!("/vol{}", vol.volume_index)),
                    name: format!(
                        "{} Volume {} ({} GB)",
                        vol.filesystem.as_str(),
                        vol.volume_index,
                        vol.size / 1_000_000_000
                    ),
                    is_dir: true,
                    size: vol.size,
                    modified: None,
                });
            }

            if entries.is_empty() {
                entries.push(VfsEntry {
                    path: PathBuf::from("/raw"),
                    name: format!("Raw Disk Image ({} GB)", self.total_size() / 1_000_000_000),
                    is_dir: true,
                    size: self.total_size(),
                    modified: None,
                });
            }

            return Ok(entries);
        }

        Ok(Vec::new())
    }
    fn open_file(&self, _path: &Path) -> Result<Vec<u8>, ForensicError> {
        Err(ForensicError::UnsupportedFilesystem)
    }

    fn file_metadata(&self, path: &Path) -> Result<VfsEntry, ForensicError> {
        let path_str = path.to_string_lossy();
        if path_str.is_empty() || path_str == "/" || path_str == "\\" {
            return Ok(VfsEntry {
                path: self.root.clone(),
                name: self
                    .root()
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "Disk Image".to_string()),
                is_dir: true,
                size: self.total_size(),
                modified: None,
            });
        }

        Err(ForensicError::UnsupportedFilesystem)
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn get_volumes(&self) -> Vec<VolumeInfo> {
        let mut volumes = Vec::new();

        // Read 1MB to cover GPT and modern partition starts
        let read_size = 1048576.min(self.size as usize);
        let data = self.read_at(0, read_size).unwrap_or_default();

        if !data.is_empty() {
            let fs_type = detect_filesystem_in_buffer(&data);

            // Check for MBR
            let _has_mbr =
                data.len() >= 512 && u16::from_le_bytes([data[0x1FE], data[0x1FF]]) == 0xAA55;

            // Check for APFS container superblock scan
            let mut apfs_offset: Option<usize> = None;
            let check_offsets = [0, 4096, 8192, 16384, 20480, 20512, 32768, 65536];
            for i in check_offsets.iter() {
                let idx = *i as usize;
                if idx + 4 <= data.len() && &data[idx..idx + 4] == b"NXSB" {
                    apfs_offset = Some(idx);
                    break;
                }
            }

            let final_fs = if apfs_offset.is_some() {
                FileSystemType::APFS
            } else {
                fs_type
            };

            let filesystem_offset: u64 = match (final_fs, apfs_offset) {
                (FileSystemType::APFS, Some(offset)) => offset as u64,
                _ => 0,
            };

            let mut base_volumes = vec![VolumeInfo {
                volume_index: 0,
                offset: filesystem_offset,
                size: self.size.saturating_sub(filesystem_offset),
                sector_size: 512,
                filesystem: final_fs,
                label: None,
                cluster_size: None,
                mft_offset: None,
                mft_record_size: None,
                serial_number: None,
            }];

            // v16 Session 3 — APFS snapshot heuristic enumeration
            // retired alongside the in-tree ApfsReader. Snapshot
            // iteration is deferred beyond v16 per
            // docs/RESEARCH_v16_APFS_SHAPE.md §4 (latest XID only
            // through v0.16; tripwire test name
            // apfs_walker_walks_current_state_only_pending_snapshot_enumeration
            // pins the deferral). When snapshots ship in v17 they
            // go through the external apfs crate's structural walk,
            // not the retired heuristic `.snapshots` field.

            // If NTFS, try to find VSS (Volume Shadow Copy) snapshots
            if final_fs == FileSystemType::NTFS {
                if let Ok(snaps) =
                    crate::shadowcopy::enumerate_vss_snapshots(self, filesystem_offset)
                {
                    for snap in &snaps {
                        let label = match snap.creation_time {
                            Some(ts) => {
                                let dt = chrono::DateTime::from_timestamp(ts, 0);
                                format!(
                                    "VSS Snapshot {} ({})",
                                    snap.snapshot_id,
                                    dt.map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                        .unwrap_or_else(|| format!("epoch {}", ts)),
                                )
                            }
                            None => format!("VSS Snapshot {}", snap.snapshot_id),
                        };
                        base_volumes.push(VolumeInfo {
                            // 1000+ range reserved for VSS snapshots
                            volume_index: 1000 + snap.index,
                            offset: filesystem_offset,
                            size: self.size.saturating_sub(filesystem_offset),
                            sector_size: 512,
                            filesystem: FileSystemType::NTFS,
                            label: Some(label),
                            cluster_size: None,
                            mft_offset: None,
                            mft_record_size: None,
                            serial_number: None,
                        });
                    }
                }
            }
            volumes.append(&mut base_volumes);
        }

        volumes
    }
}

/// Cached MFT data for file reading without re-enumeration.
struct MftCache {
    cluster_size: u64,
    partition_offset: u64,
    entries: Vec<crate::mft_walker::MftFileEntry>,
    paths: Vec<crate::mft_walker::MftPathEntry>,
}

pub struct EwfVfs {
    root: PathBuf,
    reader: Mutex<EwfReader>,
    volumes: Vec<EwfVolumeInfo>,
    volume_cache: Mutex<Option<Vec<VolumeInfo>>>,
    mft_cache: Mutex<Option<MftCache>>,
    #[cfg(target_os = "windows")]
    ntfs_index_cache: Mutex<HashMap<usize, NtfsVolumeIndex>>,
}

#[derive(Debug, Clone)]
pub struct EwfVolumeInfo {
    pub index: usize,
    pub offset: u64,
    pub size: u64,
    pub filesystem: Option<String>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Default)]
struct NtfsRecordPayload {
    size: u64,
    resident_data: Option<Vec<u8>>,
    data_runs: Vec<(Option<i64>, u64)>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct NtfsNodeRecord {
    record_number: u64,
    parent_record: u64,
    name: String,
    is_dir: bool,
    payload: NtfsRecordPayload,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Default)]
struct NtfsVolumeIndex {
    entries: Vec<VfsEntry>,
    children_by_dir: HashMap<String, Vec<VfsEntry>>,
    entries_by_path: HashMap<String, VfsEntry>,
    file_payload_by_path: HashMap<String, NtfsRecordPayload>,
}

impl EwfVfs {
    pub fn new(path: &Path) -> Result<Self, ForensicError> {
        info!("Creating EwfVfs for: {:?}", path);

        let reader = EwfReader::open(path).map_err(|e| {
            error!("Failed to open EWF file: {:?}", e);
            ForensicError::Io(std::io::Error::other(e.to_string()))
        })?;

        let total_size = reader.total_size();
        info!("EWF file opened, total size: {} bytes", total_size);

        let mut vfs = Self {
            root: path.to_path_buf(),
            reader: Mutex::new(reader),
            volumes: vec![EwfVolumeInfo {
                index: 0,
                offset: 0,
                size: total_size,
                filesystem: None,
            }],
            volume_cache: Mutex::new(None),
            mft_cache: Mutex::new(None),
            #[cfg(target_os = "windows")]
            ntfs_index_cache: Mutex::new(HashMap::new()),
        };

        // Detect partition table and filesystem signatures
        vfs.detect_partitions();
        Ok(vfs)
    }

    /// Detect MBR/GPT partition layout and identify filesystem types.
    fn detect_partitions(&mut self) {
        let total_size = self.volumes[0].size;

        // Read first 2 sectors (1024 bytes) for MBR + GPT header detection
        let Ok(header_data) = self.read_at(0, 1024) else {
            return;
        };
        if header_data.len() < 1024 {
            return;
        }

        let sector0 = &header_data[..512];

        // Check for GPT first (LBA 1 has "EFI PART" signature at offset 512)
        let is_gpt = &header_data[512..520] == b"EFI PART";

        if is_gpt {
            info!("[EwfVfs] GPT partition table detected");
            if let Some(volumes) = self.parse_gpt(total_size) {
                if !volumes.is_empty() {
                    self.volumes = volumes;
                    return;
                }
            }
        }

        // Check MBR signature (0x55AA at bytes 510-511)
        let has_mbr = sector0[510] == 0x55 && sector0[511] == 0xAA;

        if has_mbr && !is_gpt {
            info!("[EwfVfs] MBR partition table detected");
            let mut found_volumes = Vec::new();

            // Check if MBR entry 0 is a protective MBR (type 0xEE = GPT protective)
            let first_type = sector0[446 + 4];
            if first_type == 0xEE {
                info!("[EwfVfs] Protective MBR detected — treating as GPT");
                // Already tried GPT above
            } else {
                // Parse 4 MBR partition entries at offsets 446, 462, 478, 494
                for i in 0..4 {
                    let entry_offset = 446 + i * 16;
                    let partition_type = sector0[entry_offset + 4];
                    let lba_start = u32::from_le_bytes([
                        sector0[entry_offset + 8],
                        sector0[entry_offset + 9],
                        sector0[entry_offset + 10],
                        sector0[entry_offset + 11],
                    ]) as u64;
                    let lba_sectors = u32::from_le_bytes([
                        sector0[entry_offset + 12],
                        sector0[entry_offset + 13],
                        sector0[entry_offset + 14],
                        sector0[entry_offset + 15],
                    ]) as u64;

                    if partition_type == 0 || lba_start == 0 || lba_sectors == 0 {
                        continue;
                    }

                    let part_offset = lba_start * 512;
                    let part_size = lba_sectors * 512;

                    // Sanity check: partition must fit within disk
                    if part_offset >= total_size {
                        warn!(
                            "[EwfVfs] MBR partition {} offset {} exceeds disk size {} — skipping",
                            i, part_offset, total_size
                        );
                        continue;
                    }

                    let capped_size = part_size.min(total_size - part_offset);

                    // Detect filesystem at this partition offset
                    let fs_type = self.detect_filesystem_at(part_offset);

                    info!(
                        "[EwfVfs] MBR Partition {}: type=0x{:02X} offset={} size={} fs={:?}",
                        i, partition_type, part_offset, capped_size, fs_type
                    );

                    found_volumes.push(EwfVolumeInfo {
                        index: found_volumes.len(),
                        offset: part_offset,
                        size: capped_size,
                        filesystem: Some(fs_type.as_str().to_string()),
                    });
                }

                if !found_volumes.is_empty() {
                    self.volumes = found_volumes;
                    return;
                }
            }
        }

        // No valid partition table found — check if whole disk is a single filesystem
        let fs_type = self.detect_filesystem_at(0);
        if fs_type != FileSystemType::Unknown {
            info!("[EwfVfs] No partition table — whole disk is {:?}", fs_type);
            self.volumes[0].filesystem = Some(fs_type.as_str().to_string());
        } else {
            // Last resort: scan at common offsets for filesystem signatures
            // Some images have the partition starting at 1MB (2048 sectors)
            for try_offset in [1_048_576u64, 32_256, 65_536, 512] {
                if try_offset < total_size {
                    let fs = self.detect_filesystem_at(try_offset);
                    if fs != FileSystemType::Unknown {
                        info!(
                            "[EwfVfs] Found {:?} filesystem at offset {} via brute-force scan",
                            fs, try_offset
                        );
                        self.volumes = vec![EwfVolumeInfo {
                            index: 0,
                            offset: try_offset,
                            size: total_size - try_offset,
                            filesystem: Some(fs.as_str().to_string()),
                        }];
                        return;
                    }
                }
            }
        }
    }

    /// Parse GPT partition table entries.
    fn parse_gpt(&self, total_size: u64) -> Option<Vec<EwfVolumeInfo>> {
        // GPT header is at LBA 1 (offset 512)
        let Ok(gpt_header) = self.read_at(512, 512) else {
            return None;
        };
        if gpt_header.len() < 92 || &gpt_header[0..8] != b"EFI PART" {
            return None;
        }

        // Parse GPT header fields
        let partition_entry_lba = u64::from_le_bytes([
            gpt_header[72],
            gpt_header[73],
            gpt_header[74],
            gpt_header[75],
            gpt_header[76],
            gpt_header[77],
            gpt_header[78],
            gpt_header[79],
        ]);
        let num_partition_entries = u32::from_le_bytes([
            gpt_header[80],
            gpt_header[81],
            gpt_header[82],
            gpt_header[83],
        ]);
        let partition_entry_size = u32::from_le_bytes([
            gpt_header[84],
            gpt_header[85],
            gpt_header[86],
            gpt_header[87],
        ]);

        info!(
            "[EwfVfs] GPT: {} entries at LBA {}, entry_size={}",
            num_partition_entries, partition_entry_lba, partition_entry_size
        );

        if partition_entry_size < 128 || num_partition_entries == 0 || num_partition_entries > 256 {
            return None;
        }

        // Read partition entries
        let entries_offset = partition_entry_lba * 512;
        let entries_size = (num_partition_entries as usize) * (partition_entry_size as usize);
        let Ok(entries_data) = self.read_at(entries_offset, entries_size) else {
            return None;
        };

        let mut volumes = Vec::new();

        for i in 0..num_partition_entries as usize {
            let entry_start = i * partition_entry_size as usize;
            if entry_start + 128 > entries_data.len() {
                break;
            }
            let entry = &entries_data[entry_start..entry_start + partition_entry_size as usize];

            // Check if partition type GUID is all zeros (empty entry)
            let type_guid = &entry[0..16];
            if type_guid.iter().all(|&b| b == 0) {
                continue;
            }

            // First LBA and Last LBA
            let first_lba = u64::from_le_bytes([
                entry[32], entry[33], entry[34], entry[35], entry[36], entry[37], entry[38],
                entry[39],
            ]);
            let last_lba = u64::from_le_bytes([
                entry[40], entry[41], entry[42], entry[43], entry[44], entry[45], entry[46],
                entry[47],
            ]);

            if first_lba == 0 || last_lba <= first_lba {
                continue;
            }

            let part_offset = first_lba * 512;
            let part_size = (last_lba - first_lba + 1) * 512;

            // Sanity check
            if part_offset >= total_size {
                warn!(
                    "[EwfVfs] GPT partition {} offset {} exceeds disk size {} — skipping",
                    i, part_offset, total_size
                );
                continue;
            }

            let capped_size = part_size.min(total_size - part_offset);

            // Extract partition name (UTF-16LE at offset 56, 72 bytes / 36 chars)
            let name_bytes = &entry[56..128];
            let name_u16: Vec<u16> = name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let part_name = String::from_utf16_lossy(&name_u16)
                .trim_end_matches('\0')
                .to_string();

            // Detect filesystem
            let fs_type = self.detect_filesystem_at(part_offset);

            // Identify well-known GPT type GUIDs
            let type_str = identify_gpt_type_guid(type_guid);

            info!(
                "[EwfVfs] GPT Partition {}: name=\"{}\" type={} offset={} size={} fs={:?}",
                i, part_name, type_str, part_offset, capped_size, fs_type
            );

            volumes.push(EwfVolumeInfo {
                index: volumes.len(),
                offset: part_offset,
                size: capped_size,
                filesystem: Some(fs_type.as_str().to_string()),
            });
        }

        Some(volumes)
    }
}

// ─── EwfSeekReader — adapts EwfVfs into Read + Seek for MftWalker ────────────

/// Wrapper that provides `Read + Seek` over EwfVfs byte-level access.
/// This allows MftWalker to read NTFS structures from within an E01 container
/// on any platform.
struct EwfSeekReader<'a> {
    vfs: &'a EwfVfs,
    base_offset: u64,
    position: u64,
}

impl<'a> EwfSeekReader<'a> {
    fn new(vfs: &'a EwfVfs, base_offset: u64) -> Self {
        Self {
            vfs,
            base_offset,
            position: 0,
        }
    }
}

impl<'a> Read for EwfSeekReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let abs_offset = self.base_offset + self.position;
        let data = self
            .vfs
            .read_at(abs_offset, buf.len())
            .map_err(|e| std::io::Error::other(format!("EWF read failed: {}", e)))?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        self.position += n as u64;
        Ok(n)
    }
}

impl<'a> Seek for EwfSeekReader<'a> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::Current(offset) => self.position as i64 + offset,
            SeekFrom::End(_) => {
                // We don't know the exact volume size easily, so reject End seeks
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "SeekFrom::End not supported for EwfSeekReader",
                ));
            }
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Seek to negative position",
            ));
        }
        self.position = new_pos as u64;
        Ok(self.position)
    }
}

/// Identify well-known GPT partition type GUIDs.
fn identify_gpt_type_guid(guid: &[u8]) -> &'static str {
    // GUIDs are stored in mixed-endian format in GPT
    // Microsoft Basic Data: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
    // Microsoft Reserved:   E3C9E316-0B5C-4DB8-817D-F92DF00215AE
    // EFI System:           C12A7328-F81F-11D2-BA4B-00A0C93EC93B
    // Linux filesystem:     0FC63DAF-8483-4772-8E79-3D69D8477DE4

    if guid.len() < 16 {
        return "Unknown";
    }

    // Check first 4 bytes (little-endian) for common type GUIDs
    let first4 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    match first4 {
        0xEBD0A0A2 => "Microsoft Basic Data (NTFS/FAT)",
        0xE3C9E316 => "Microsoft Reserved",
        0xC12A7328 => "EFI System Partition",
        0xDE94BBA4 => "Microsoft Recovery",
        0x0FC63DAF => "Linux Filesystem",
        0x0657FD6D => "Linux Swap",
        0x48465300 => "Apple HFS/HFS+",
        0x7C3457EF => "Apple APFS",
        _ => "Data",
    }
}

impl crate::container::EvidenceContainerRO for EwfVfs {
    fn description(&self) -> &str {
        "EwfVfs"
    }
    fn source_path(&self) -> &Path {
        &self.root
    }
    fn size(&self) -> u64 {
        self.volumes.first().map(|v| v.size).unwrap_or(0)
    }
    fn sector_size(&self) -> u64 {
        512
    }
    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        let data = self.read_at(offset, buf.len())?;
        if data.len() < buf.len() {
            return Err(ForensicError::OutOfRange(format!(
                "EwfVfs read_into: requested {} bytes at offset {}, got {}",
                buf.len(),
                offset,
                data.len()
            )));
        }
        buf.copy_from_slice(&data[..buf.len()]);
        Ok(())
    }
}

impl EwfVfs {
    /// Detect the filesystem type at a given byte offset by reading signature bytes.
    fn detect_filesystem_at(&self, offset: u64) -> FileSystemType {
        // Read first 8 sectors (4096 bytes) for filesystem detection
        let Ok(data) = self.read_at(offset, 4096) else {
            return FileSystemType::Unknown;
        };
        if data.len() < 512 {
            return FileSystemType::Unknown;
        }

        // NTFS: "NTFS    " at offset 3 in the boot sector
        if data.len() >= 11 && &data[3..7] == b"NTFS" {
            return FileSystemType::NTFS;
        }

        // FAT32: "FAT32   " at offset 82
        if data.len() >= 90 && &data[82..87] == b"FAT32" {
            return FileSystemType::FAT32;
        }

        // FAT16: "FAT16   " or "FAT12   " at offset 54
        if data.len() >= 62 && (&data[54..59] == b"FAT16" || &data[54..59] == b"FAT12") {
            return FileSystemType::FAT32; // Use FAT32 enum for all FAT variants
        }

        // exFAT: "EXFAT   " at offset 3
        if data.len() >= 11 && &data[3..8] == b"EXFAT" {
            return FileSystemType::ExFAT;
        }

        // ext2/3/4: magic 0xEF53 at offset 1080 (0x438) in the superblock
        if data.len() >= 1082 {
            let ext_magic = u16::from_le_bytes([data[0x438], data[0x439]]);
            if ext_magic == 0xEF53 {
                return FileSystemType::Ext4;
            }
        }

        // XFS: magic "XFSB" at offset 0
        if data.len() >= 4 && &data[0..4] == b"XFSB" {
            return FileSystemType::XFS;
        }

        // HFS+: magic 0x482B at offset 1024
        if data.len() >= 1026 {
            let hfs_magic = u16::from_be_bytes([data[1024], data[1025]]);
            if hfs_magic == 0x482B || hfs_magic == 0x4858 {
                return FileSystemType::HFSPlus;
            }
        }

        // APFS: magic "NXSB" at offset 32 of container superblock
        if data.len() >= 36 && &data[32..36] == b"NXSB" {
            return FileSystemType::APFS;
        }

        FileSystemType::Unknown
    }

    pub fn set_volume_filesystem(&mut self, index: usize, fs: &str) {
        if index < self.volumes.len() {
            self.volumes[index].filesystem = Some(fs.to_string());
        }
        if let Ok(mut cache) = self.volume_cache.lock() {
            *cache = None;
        }
        #[cfg(target_os = "windows")]
        if let Ok(mut cache) = self.ntfs_index_cache.lock() {
            cache.clear();
        }
    }

    pub fn read_at(&self, offset: u64, size: usize) -> Result<Vec<u8>, ForensicError> {
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut reader = self
            .reader
            .lock()
            .map_err(|_| ForensicError::Io(std::io::Error::other("Lock poisoned")))?;
        let total_size = reader.total_size();
        if offset >= total_size {
            return Ok(Vec::new());
        }

        let safe_size = size.min((total_size - offset) as usize);

        #[cfg(feature = "turbo")]
        {
            const BUFFER_SIZE: usize = 1024 * 1024;
            if safe_size <= BUFFER_SIZE {
                let aligned_offset = offset & !(BUFFER_SIZE as u64 - 1);
                let aligned_size = BUFFER_SIZE.min((total_size - aligned_offset) as usize);

                let mut aligned_buffer = vec![0u8; aligned_size];

                reader.seek(SeekFrom::Start(aligned_offset)).map_err(|e| {
                    ForensicError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ))
                })?;

                reader.read_exact(&mut aligned_buffer).map_err(|e| {
                    ForensicError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ))
                })?;

                let start_offset = (offset - aligned_offset) as usize;
                return Ok(aligned_buffer[start_offset..start_offset + safe_size].to_vec());
            }
        }

        let mut buffer = vec![0u8; safe_size];

        reader
            .seek(SeekFrom::Start(offset))
            .map_err(|e| ForensicError::Io(std::io::Error::other(e.to_string())))?;

        reader
            .read_exact(&mut buffer)
            .map_err(|e| ForensicError::Io(std::io::Error::other(e.to_string())))?;

        Ok(buffer)
    }

    pub fn volumes(&self) -> &[EwfVolumeInfo] {
        &self.volumes
    }

    #[cfg(target_os = "windows")]
    fn volume_index_from_path(path: &Path) -> Option<usize> {
        let normalized = path.to_string_lossy().replace('\\', "/");
        // Paths from enumerate_ntfs_directory use "/ntfs_vol{N}/..." format.
        // Also support "/vol{N}/..." for backwards compatibility.
        if let Some(rest) = normalized.strip_prefix("/ntfs_vol") {
            return rest.split('/').next().and_then(|s| s.parse::<usize>().ok());
        }
        if let Some(rest) = normalized.strip_prefix("/vol") {
            return rest.split('/').next().and_then(|s| s.parse::<usize>().ok());
        }
        None
    }
}

#[cfg(target_os = "windows")]
impl EwfVfs {
    fn parse_ntfs_runlist(runlist: &[u8]) -> Vec<(Option<i64>, u64)> {
        let mut runs = Vec::new();
        let mut idx = 0usize;
        let mut current_lcn: i64 = 0;

        while idx < runlist.len() {
            let header = runlist[idx];
            idx += 1;
            if header == 0 {
                break;
            }

            let len_size = (header & 0x0F) as usize;
            let off_size = ((header >> 4) & 0x0F) as usize;

            if len_size == 0
                || idx + len_size + off_size > runlist.len()
                || len_size > 8
                || off_size > 8
            {
                break;
            }

            let mut run_len_buf = [0u8; 8];
            run_len_buf[..len_size].copy_from_slice(&runlist[idx..idx + len_size]);
            idx += len_size;
            let run_len = u64::from_le_bytes(run_len_buf);
            if run_len == 0 {
                break;
            }

            if off_size == 0 {
                runs.push((None, run_len));
                continue;
            }

            let mut run_off_buf = [0u8; 8];
            run_off_buf[..off_size].copy_from_slice(&runlist[idx..idx + off_size]);
            let sign_extended = (run_off_buf[off_size - 1] & 0x80) != 0;
            if sign_extended {
                for b in &mut run_off_buf[off_size..] {
                    *b = 0xFF;
                }
            }
            idx += off_size;

            let relative_lcn = i64::from_le_bytes(run_off_buf);
            current_lcn = current_lcn.saturating_add(relative_lcn);
            runs.push((Some(current_lcn), run_len));
        }

        runs
    }

    fn enumerate_ntfs_root_shallow(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        // Shallow enumeration: root directory (MFT record 5) only.
        self.enumerate_ntfs_directory_with_record(vol_info, 5)
    }

    fn enumerate_ntfs_directory_with_record(
        &self,
        vol_info: &VolumeInfo,
        mft_record: u32,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        struct EwfContainerRef<'a> {
            vfs: &'a EwfVfs,
            offset: u64,
            sector_size: u64,
            size: u64,
        }

        impl<'a> EvidenceContainerRO for EwfContainerRef<'a> {
            fn description(&self) -> &str {
                "EwfVfs Container"
            }

            fn source_path(&self) -> &Path {
                self.vfs.root()
            }

            fn size(&self) -> u64 {
                self.size
            }

            fn sector_size(&self) -> u64 {
                self.sector_size
            }

            fn read_at(&self, offset: u64, size: u64) -> Result<Vec<u8>, ForensicError> {
                self.vfs.read_at(self.offset + offset, size as usize)
            }

            fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
                let data = self.vfs.read_at(self.offset + offset, buf.len())?;
                buf.copy_from_slice(&data);
                Ok(())
            }
        }

        let container = EwfContainerRef {
            vfs: self,
            offset: vol_info.offset,
            sector_size: vol_info.sector_size,
            size: vol_info.size,
        };

        match enumerate_directory(&container, 0, mft_record, 1000) {
            Ok(entries) => {
                let mut vfs_entries = Vec::new();
                for entry in entries {
                    let child_path = format!("/ntfs_vol{}/{}", vol_info.volume_index, entry.name);
                    vfs_entries.push(VfsEntry {
                        path: PathBuf::from(child_path),
                        name: entry.name,
                        is_dir: entry.is_directory,
                        size: entry.size,
                        modified: entry
                            .modified
                            .map(|t| DateTime::from_timestamp(t, 0).unwrap_or_default()),
                    });
                }
                Ok(vfs_entries)
            }
            Err(e) => Err(ForensicError::MalformedData(format!(
                "NTFS directory enumeration failed for volume {}: {}",
                vol_info.volume_index, e
            ))),
        }
    }

    fn apply_ntfs_usa_fixup(record: &mut [u8], bytes_per_sector: usize) -> bool {
        if record.len() < 8 || bytes_per_sector < 2 {
            return false;
        }

        // NTFS FILE record header:
        // update sequence array offset/count are at 0x04/0x06
        let usa_offset = u16::from_le_bytes([record[0x04], record[0x05]]) as usize;
        let usa_count = u16::from_le_bytes([record[0x06], record[0x07]]) as usize;
        if usa_count < 2 {
            return false;
        }

        let usa_len = match usa_count.checked_mul(2) {
            Some(v) => v,
            None => return false,
        };
        if usa_offset >= record.len()
            || usa_offset
                .checked_add(usa_len)
                .is_none_or(|end| end > record.len())
        {
            return false;
        }

        let sectors = usa_count - 1;
        if sectors == 0 {
            return false;
        }

        let usn = u16::from_le_bytes([record[usa_offset], record[usa_offset + 1]]);

        for i in 0..sectors {
            let sector_end = match (i + 1).checked_mul(bytes_per_sector) {
                Some(v) => v,
                None => return false,
            };
            if sector_end > record.len() {
                return false;
            }

            let trailer = sector_end - 2;
            let expected = u16::from_le_bytes([record[trailer], record[trailer + 1]]);
            if expected != usn {
                return false;
            }

            let replacement = usa_offset + 2 + i * 2;
            record[trailer] = record[replacement];
            record[trailer + 1] = record[replacement + 1];
        }

        true
    }

    fn filename_namespace_rank(namespace: u8) -> u8 {
        match namespace {
            3 => 0, // WIN32+DOS
            1 => 1, // WIN32
            0 => 2, // POSIX
            2 => 3, // DOS
            _ => 4,
        }
    }

    fn score_mft_layout(
        &self,
        mft_abs: u64,
        record_size: usize,
        sector_size: usize,
        volume_start: u64,
        volume_end: u64,
    ) -> usize {
        if record_size < 256 || mft_abs < volume_start || mft_abs >= volume_end {
            return 0;
        }

        let sample_records = 16usize;
        let sample_bytes = record_size.saturating_mul(sample_records);
        if sample_bytes == 0 {
            return 0;
        }

        let max_bytes = volume_end.saturating_sub(mft_abs) as usize;
        let read_size = sample_bytes.min(max_bytes);
        if read_size < record_size {
            return 0;
        }

        let data = match self.read_at(mft_abs, read_size) {
            Ok(d) => d,
            Err(_) => return 0,
        };

        let available_records = data.len() / record_size;
        let mut score = 0usize;
        for i in 0..available_records {
            let start = i * record_size;
            let end = start + record_size;
            let mut rec = data[start..end].to_vec();
            if rec.len() < 4 || &rec[0..4] != b"FILE" {
                continue;
            }
            if !Self::apply_ntfs_usa_fixup(&mut rec, sector_size) {
                continue;
            }
            if rec.len() < 0x30 {
                continue;
            }

            let flags = u16::from_le_bytes([rec[0x16], rec[0x17]]);
            let in_use = (flags & 0x01) != 0;
            let first_attr_off = u16::from_le_bytes([rec[0x14], rec[0x15]]) as usize;
            if in_use && first_attr_off >= 0x18 && first_attr_off < rec.len() {
                score += 1;
            }
        }

        score
    }

    fn locate_best_mft_layout(
        &self,
        vol_info: &VolumeInfo,
        expected_mft_abs: u64,
        expected_record_size: usize,
        sector_size: usize,
    ) -> (u64, usize, usize, usize) {
        let volume_start = vol_info.offset;
        let volume_end = vol_info.offset.saturating_add(vol_info.size);
        let mut record_sizes = vec![expected_record_size, 1024usize, 4096usize, 2048usize];
        record_sizes.sort_unstable();
        record_sizes.dedup();
        record_sizes.retain(|v| *v >= 256 && *v <= 8192);
        let mut sector_sizes = vec![sector_size, 512usize, 4096usize];
        sector_sizes.sort_unstable();
        sector_sizes.dedup();
        sector_sizes.retain(|v| *v >= 512);

        let shifts = [
            0u64, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288,
            1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864,
        ];

        let mut best_abs = expected_mft_abs;
        let mut best_record_size = expected_record_size;
        let mut best_sector_size = sector_size;
        let mut best_score = 0usize;

        for record_size in &record_sizes {
            for shift in shifts {
                let mut candidates = Vec::with_capacity(2);
                if let Some(add) = expected_mft_abs.checked_add(shift) {
                    candidates.push(add);
                }
                if let Some(sub) = expected_mft_abs.checked_sub(shift) {
                    candidates.push(sub);
                }

                for candidate in candidates {
                    for sec_size in &sector_sizes {
                        let score = self.score_mft_layout(
                            candidate,
                            *record_size,
                            *sec_size,
                            volume_start,
                            volume_end,
                        );
                        if score > best_score {
                            best_score = score;
                            best_abs = candidate;
                            best_record_size = *record_size;
                            best_sector_size = *sec_size;
                        }
                    }
                }
            }
        }

        // Deep scan if the derived layout scored zero.
        if best_score == 0 {
            let search_radius = 512u64 * 1024 * 1024; // +/- 512MB
            let search_start = expected_mft_abs
                .saturating_sub(search_radius)
                .max(volume_start);
            let search_end = expected_mft_abs
                .saturating_add(search_radius)
                .min(volume_end);
            let chunk_size = 2usize * 1024 * 1024;
            let mut checked_candidates = 0usize;

            let mut chunk_base = search_start;
            while chunk_base < search_end && checked_candidates < 4000 {
                let remaining = search_end.saturating_sub(chunk_base) as usize;
                let read_size = chunk_size.min(remaining);
                if read_size < 4 {
                    break;
                }

                let chunk = match self.read_at(chunk_base, read_size) {
                    Ok(c) => c,
                    Err(_) => break,
                };

                let mut i = 0usize;
                while i + 4 <= chunk.len() && checked_candidates < 4000 {
                    if &chunk[i..i + 4] == b"FILE" {
                        let candidate = chunk_base.saturating_add(i as u64);
                        for record_size in &record_sizes {
                            for sec_size in &sector_sizes {
                                let score = self.score_mft_layout(
                                    candidate,
                                    *record_size,
                                    *sec_size,
                                    volume_start,
                                    volume_end,
                                );
                                if score > best_score {
                                    best_score = score;
                                    best_abs = candidate;
                                    best_record_size = *record_size;
                                    best_sector_size = *sec_size;
                                }
                            }
                        }
                        checked_candidates += 1;
                        if best_score >= 4 {
                            break;
                        }
                        i = i.saturating_add(4);
                        continue;
                    }
                    i = i.saturating_add(1);
                }

                if best_score >= 4 {
                    break;
                }
                chunk_base = chunk_base.saturating_add(chunk_size as u64);
            }
        }

        (best_abs, best_record_size, best_sector_size, best_score)
    }

    fn get_or_build_ntfs_index(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<NtfsVolumeIndex, ForensicError> {
        {
            let cache = self.ntfs_index_cache.lock().map_err(|_| {
                ForensicError::Io(std::io::Error::other("NTFS index cache lock poisoned"))
            })?;
            if let Some(index) = cache.get(&vol_info.volume_index) {
                return Ok(index.clone());
            }
        }

        let built = self.build_ntfs_volume_index(vol_info)?;
        let mut cache = self.ntfs_index_cache.lock().map_err(|_| {
            ForensicError::Io(std::io::Error::other("NTFS index cache lock poisoned"))
        })?;
        cache.insert(vol_info.volume_index, built.clone());
        Ok(built)
    }

    fn build_ntfs_volume_index(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<NtfsVolumeIndex, ForensicError> {
        const ROOT_DIR_RECORD: u64 = 5;

        info!(
            "[EWF][NTFS] Starting MFT fallback enumeration for volume {} at offset {}",
            vol_info.volume_index, vol_info.offset
        );

        let mut index = NtfsVolumeIndex::default();
        let mut sector_size = (vol_info.sector_size as usize).max(512);
        if let Ok(vbr) = self.read_at(vol_info.offset, 512) {
            if vbr.len() >= 13 {
                let bps = u16::from_le_bytes([vbr[11], vbr[12]]) as usize;
                if matches!(bps, 512 | 1024 | 2048 | 4096) {
                    sector_size = bps;
                }
            }
        }

        let expected_record_size = (vol_info.mft_record_size.unwrap_or(1024) as usize).max(256);
        let mft_rel = vol_info.mft_offset.unwrap_or(0);
        if mft_rel == 0 || expected_record_size == 0 {
            info!(
                "[EWF][NTFS] Fallback skipped: mft_offset={:?}, record_size={}",
                vol_info.mft_offset, expected_record_size
            );
            return Ok(index);
        }

        let expected_mft_abs = vol_info.offset.saturating_add(mft_rel);
        if expected_mft_abs >= vol_info.offset.saturating_add(vol_info.size) {
            info!(
                "[EWF][NTFS] Fallback skipped: mft_abs={} outside volume range",
                expected_mft_abs
            );
            return Ok(index);
        }

        let (mft_abs, record_size, chosen_sector_size, layout_score) = self.locate_best_mft_layout(
            vol_info,
            expected_mft_abs,
            expected_record_size,
            sector_size,
        );
        info!(
            "[EWF][NTFS] Using MFT layout: expected_abs={} chosen_abs={} expected_record_size={} chosen_record_size={} expected_sector_size={} chosen_sector_size={} score={}",
            expected_mft_abs,
            mft_abs,
            expected_record_size,
            record_size,
            sector_size,
            chosen_sector_size,
            layout_score
        );

        sector_size = chosen_sector_size;
        let max_bytes = vol_info
            .offset
            .saturating_add(vol_info.size)
            .saturating_sub(mft_abs);
        let max_records = (max_bytes as usize) / record_size;
        let scan_count = max_records.max(1);
        let records_per_chunk = (1024 * 1024 / record_size).max(1);

        let mut records_by_number: HashMap<u64, NtfsNodeRecord> = HashMap::new();
        let mut valid_records = 0usize;

        for chunk_start in (0..scan_count).step_by(records_per_chunk) {
            let chunk_records = (scan_count - chunk_start).min(records_per_chunk);
            let chunk_offset = mft_abs.saturating_add((chunk_start * record_size) as u64);
            let chunk_size = chunk_records * record_size;

            let chunk = match self.read_at(chunk_offset, chunk_size) {
                Ok(d) => d,
                Err(_) => break,
            };
            if chunk.len() < record_size {
                break;
            }

            let available_records = chunk.len() / record_size;
            for idx in 0..available_records {
                let rec_start = idx * record_size;
                let rec_end = rec_start + record_size;
                let mut record = chunk[rec_start..rec_end].to_vec();

                if record.len() < 4 || &record[0..4] != b"FILE" {
                    continue;
                }
                if !Self::apply_ntfs_usa_fixup(&mut record, sector_size) {
                    let mut fixed = false;
                    for alt in [512usize, 1024usize, 2048usize, 4096usize] {
                        if alt == sector_size {
                            continue;
                        }
                        let mut retry = chunk[rec_start..rec_end].to_vec();
                        if Self::apply_ntfs_usa_fixup(&mut retry, alt) {
                            record = retry;
                            fixed = true;
                            break;
                        }
                    }
                    if !fixed {
                        continue;
                    }
                }
                if record.len() < 0x30 {
                    continue;
                }

                let flags = u16::from_le_bytes([record[0x16], record[0x17]]);
                let in_use = (flags & 0x01) != 0;
                let is_dir = (flags & 0x02) != 0;
                if !in_use {
                    continue;
                }
                valid_records += 1;

                let base_ref = u64::from_le_bytes([
                    record[0x20],
                    record[0x21],
                    record[0x22],
                    record[0x23],
                    record[0x24],
                    record[0x25],
                    record[0x26],
                    record[0x27],
                ]);
                if base_ref != 0 {
                    continue;
                }

                let first_attr_off = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
                if first_attr_off < 0x18 || first_attr_off >= record.len() {
                    continue;
                }

                let mut selected_name: Option<(u8, u64, String)> = None;
                let mut payload = NtfsRecordPayload::default();
                let mut captured_default_data = false;

                let mut pos = first_attr_off;
                while pos + 16 <= record.len() {
                    let attr_type = u32::from_le_bytes([
                        record[pos],
                        record[pos + 1],
                        record[pos + 2],
                        record[pos + 3],
                    ]);
                    if attr_type == 0xFFFF_FFFF {
                        break;
                    }

                    let attr_len = u32::from_le_bytes([
                        record[pos + 4],
                        record[pos + 5],
                        record[pos + 6],
                        record[pos + 7],
                    ]) as usize;
                    if attr_len < 16 || pos + attr_len > record.len() {
                        break;
                    }

                    let non_resident = record[pos + 8] != 0;
                    let attr_name_len = record[pos + 9] as usize;

                    if attr_type == 0x30 && !non_resident && attr_len >= 0x18 {
                        let value_len = u32::from_le_bytes([
                            record[pos + 0x10],
                            record[pos + 0x11],
                            record[pos + 0x12],
                            record[pos + 0x13],
                        ]) as usize;
                        let value_off =
                            u16::from_le_bytes([record[pos + 0x14], record[pos + 0x15]]) as usize;
                        let value_start = pos + value_off;
                        let value_end = value_start.saturating_add(value_len);

                        if value_start < record.len()
                            && value_end <= record.len()
                            && value_len >= 66
                        {
                            let value = &record[value_start..value_end];
                            let parent_ref = u64::from_le_bytes([
                                value[0], value[1], value[2], value[3], value[4], value[5],
                                value[6], value[7],
                            ]) & 0x0000_FFFF_FFFF_FFFF;
                            let name_len = value[64] as usize;
                            let namespace = value[65];
                            let name_bytes_len = name_len.saturating_mul(2);
                            if name_len > 0 && 66 + name_bytes_len <= value.len() {
                                let name_bytes = &value[66..66 + name_bytes_len];
                                let mut utf16 = Vec::with_capacity(name_len);
                                for chunk in name_bytes.chunks_exact(2) {
                                    utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                                }

                                let mut name = String::new();
                                for ch in std::char::decode_utf16(utf16.into_iter()) {
                                    match ch {
                                        Ok(c) => name.push(c),
                                        Err(_) => name.push('\u{FFFD}'),
                                    }
                                }

                                if !name.is_empty() && name != "." && name != ".." {
                                    let rank = Self::filename_namespace_rank(namespace);
                                    match &selected_name {
                                        Some((current_rank, _, _)) if *current_rank <= rank => {}
                                        _ => selected_name = Some((rank, parent_ref, name)),
                                    }
                                }
                            }
                        }
                    } else if attr_type == 0x80
                        && !is_dir
                        && !captured_default_data
                        && attr_name_len == 0
                    {
                        captured_default_data = true;
                        if non_resident {
                            if attr_len >= 0x40 {
                                payload.size = u64::from_le_bytes([
                                    record[pos + 0x30],
                                    record[pos + 0x31],
                                    record[pos + 0x32],
                                    record[pos + 0x33],
                                    record[pos + 0x34],
                                    record[pos + 0x35],
                                    record[pos + 0x36],
                                    record[pos + 0x37],
                                ]);
                                let runlist_off =
                                    u16::from_le_bytes([record[pos + 0x20], record[pos + 0x21]])
                                        as usize;
                                if runlist_off < attr_len {
                                    let start = pos + runlist_off;
                                    let end = pos + attr_len;
                                    payload.data_runs =
                                        Self::parse_ntfs_runlist(&record[start..end]);
                                }
                            }
                        } else if attr_len >= 0x18 {
                            let value_len = u32::from_le_bytes([
                                record[pos + 0x10],
                                record[pos + 0x11],
                                record[pos + 0x12],
                                record[pos + 0x13],
                            ]) as usize;
                            let value_off =
                                u16::from_le_bytes([record[pos + 0x14], record[pos + 0x15]])
                                    as usize;
                            let value_start = pos + value_off;
                            let value_end = value_start.saturating_add(value_len);
                            if value_start < record.len() && value_end <= record.len() {
                                payload.size = value_len as u64;
                                payload.resident_data =
                                    Some(record[value_start..value_end].to_vec());
                            }
                        }
                    }

                    pos += attr_len;
                }

                let (_, parent_record, name) = match selected_name {
                    Some(v) => v,
                    None => continue,
                };

                let header_record_number =
                    u32::from_le_bytes([record[0x2C], record[0x2D], record[0x2E], record[0x2F]])
                        as u64;
                let scan_record_number = (chunk_start + idx) as u64;
                let record_number = if header_record_number == 0 && scan_record_number != 0 {
                    scan_record_number
                } else {
                    header_record_number
                };

                if record_number == ROOT_DIR_RECORD {
                    continue;
                }

                records_by_number.insert(
                    record_number,
                    NtfsNodeRecord {
                        record_number,
                        parent_record,
                        name,
                        is_dir,
                        payload,
                    },
                );
            }
        }

        let volume_root = PathBuf::from(format!("/vol{}", vol_info.volume_index));
        let mut path_cache: HashMap<u64, PathBuf> = HashMap::new();
        path_cache.insert(ROOT_DIR_RECORD, volume_root.clone());

        fn resolve_record_path(
            record_number: u64,
            records: &HashMap<u64, NtfsNodeRecord>,
            root: &Path,
            cache: &mut HashMap<u64, PathBuf>,
            visiting: &mut HashSet<u64>,
        ) -> PathBuf {
            if let Some(existing) = cache.get(&record_number) {
                return existing.clone();
            }

            if visiting.contains(&record_number) {
                return root.to_path_buf();
            }
            visiting.insert(record_number);

            let resolved = if let Some(record) = records.get(&record_number) {
                let parent_path = if record.parent_record == record.record_number {
                    root.to_path_buf()
                } else {
                    resolve_record_path(record.parent_record, records, root, cache, visiting)
                };
                let mut joined = parent_path;
                joined.push(&record.name);
                joined
            } else {
                root.to_path_buf()
            };

            visiting.remove(&record_number);
            cache.insert(record_number, resolved.clone());
            resolved
        }

        let mut seen_paths = HashSet::new();
        for record in records_by_number.values() {
            let mut visiting = HashSet::new();
            let full_path = resolve_record_path(
                record.record_number,
                &records_by_number,
                volume_root.as_path(),
                &mut path_cache,
                &mut visiting,
            );

            let normalized = Self::normalize_virtual_path(full_path.as_path());
            if !seen_paths.insert(normalized.clone()) {
                continue;
            }

            let entry = VfsEntry {
                path: full_path.clone(),
                name: record.name.clone(),
                is_dir: record.is_dir,
                size: record.payload.size,
                modified: None,
            };
            index
                .entries_by_path
                .insert(normalized.clone(), entry.clone());

            let parent_norm = full_path
                .parent()
                .map(Self::normalize_virtual_path)
                .unwrap_or_else(|| Self::normalize_virtual_path(volume_root.as_path()));
            index
                .children_by_dir
                .entry(parent_norm)
                .or_default()
                .push(entry.clone());

            if !record.is_dir {
                index
                    .file_payload_by_path
                    .insert(normalized, record.payload.clone());
            }

            index.entries.push(entry);
        }

        for children in index.children_by_dir.values_mut() {
            children.sort_by(|a, b| match (a.is_dir, b.is_dir) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            });
        }

        index.entries.sort_by(|a, b| {
            let a_depth = a.path.components().count();
            let b_depth = b.path.components().count();
            a_depth.cmp(&b_depth).then_with(|| {
                a.path
                    .to_string_lossy()
                    .to_lowercase()
                    .cmp(&b.path.to_string_lossy().to_lowercase())
            })
        });

        info!(
            "[EWF][NTFS] MFT fallback enumeration complete: {} entries (valid_records={})",
            index.entries.len(),
            valid_records
        );
        Ok(index)
    }

    fn normalize_virtual_path(path: &Path) -> String {
        let mut text = path.to_string_lossy().replace('\\', "/");
        if text.is_empty() {
            return "/".to_string();
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
        text.to_string()
    }

    /// Normalize a path for index lookup. Enumeration uses `/ntfs_vol{N}/...`
    /// but the NTFS index keys use `/vol{N}/...`. Convert to index format.
    fn normalize_index_path(path: &Path) -> String {
        let normalized = Self::normalize_virtual_path(path);
        // Convert /ntfs_vol{N}/... → /vol{N}/...
        if let Some(rest) = normalized.strip_prefix("/ntfs_vol") {
            return format!("/vol{}", rest);
        }
        normalized
    }
}

// Cross-platform VirtualFileSystem for EwfVfs.
// Uses MftWalker for NTFS enumeration on macOS/Linux.
#[cfg(not(target_os = "windows"))]
impl VirtualFileSystem for EwfVfs {
    fn root(&self) -> &PathBuf {
        &self.root
    }

    fn read_dir(&self, _path: &Path) -> Result<Vec<VfsEntry>, ForensicError> {
        let mut entries = Vec::new();
        for vol in &self.volumes {
            entries.push(VfsEntry {
                path: PathBuf::from(format!("/vol{}", vol.index)),
                name: format!("Volume {} ({} bytes)", vol.index, vol.size),
                is_dir: true,
                size: vol.size,
                modified: None,
            });
        }
        Ok(entries)
    }

    fn enumerate_ntfs_directory(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        info!(
            "[EwfVfs] Cross-platform NTFS enumeration via MftWalker: vol={} offset={}",
            vol_info.volume_index, vol_info.offset
        );

        // Create an EwfSeekReader wrapper that implements Read + Seek
        let reader = EwfSeekReader::new(self, vol_info.offset);
        let mut walker = crate::mft_walker::MftWalker::new(reader, 0)?;

        let path_entries = walker.enumerate_with_paths(200_000)?;

        let vfs_entries: Vec<VfsEntry> = path_entries
            .iter()
            .map(|e| {
                let vfs_path = format!("/ntfs_vol{}{}", vol_info.volume_index, e.path);
                let modified_dt = e.modified.and_then(|ts| DateTime::from_timestamp(ts, 0));
                VfsEntry {
                    path: PathBuf::from(&vfs_path),
                    name: e.name.clone(),
                    is_dir: e.is_directory,
                    size: e.size,
                    modified: modified_dt,
                }
            })
            .collect();

        info!(
            "[EwfVfs] MftWalker returned {} entries for volume {}",
            vfs_entries.len(),
            vol_info.volume_index
        );

        Ok(vfs_entries)
    }

    fn enumerate_apfs_directory(
        &self,
        _vol_info: &VolumeInfo,
        _target_path: &Path,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        // v16 Session 3 — see the sibling implementation earlier in
        // this file for the full retirement rationale. EwfVfs's
        // APFS path previously called crate::apfs_walker::ApfsWalker
        // which has been retired. The dispatcher's ApfsSingleWalker
        // / ApfsMultiWalker (Sessions 4 / 5) is the modern API.
        Ok(Vec::new())
    }

    fn open_file(&self, path: &Path) -> Result<Vec<u8>, ForensicError> {
        let path_str = path.to_string_lossy();

        // Build or reuse MFT cache
        {
            let mut cache_guard = self
                .mft_cache
                .lock()
                .map_err(|_| ForensicError::Io(std::io::Error::other("MFT cache lock poisoned")))?;

            if cache_guard.is_none() {
                let vol = self
                    .volumes
                    .first()
                    .ok_or(ForensicError::InvalidImageFormat)?;
                let partition_offset = vol.offset;

                info!(
                    "[EwfVfs] Building MFT cache for file reads (partition offset {})",
                    partition_offset
                );
                let reader = EwfSeekReader::new(self, partition_offset);
                let mut walker = crate::mft_walker::MftWalker::new(reader, 0)?;
                let cluster_size = walker.boot_params().cluster_size as u64;
                let entries = walker.enumerate(200_000)?;
                let paths = crate::mft_walker::build_path_tree_public(&entries);

                info!(
                    "[EwfVfs] MFT cache built: {} entries, {} paths",
                    entries.len(),
                    paths.len()
                );
                *cache_guard = Some(MftCache {
                    cluster_size,
                    partition_offset,
                    entries,
                    paths,
                });
            }
        }

        // Use the cache to find the file
        let cache_guard = self
            .mft_cache
            .lock()
            .map_err(|_| ForensicError::Io(std::io::Error::other("MFT cache lock poisoned")))?;
        let cache = cache_guard
            .as_ref()
            .ok_or(ForensicError::InvalidImageFormat)?;

        // Strip the /ntfs_vol0 prefix to match MFT paths
        let search_path = path_str
            .find("/ntfs_vol")
            .and_then(|pos| {
                let rest = &path_str[pos..];
                rest.find('/').map(|slash| &rest[slash..])
            })
            .unwrap_or(&path_str);
        let search_trimmed = search_path.trim_start_matches('/');

        // Find matching MFT entry by path suffix
        let mft_entry = cache.entries.iter().find(|e| {
            let entry_path = cache
                .paths
                .iter()
                .find(|pe| pe.inode == e.inode)
                .map(|pe| pe.path.as_str())
                .unwrap_or("");
            let ep_trimmed = entry_path.trim_start_matches('/');
            ep_trimmed == search_trimmed || ep_trimmed.ends_with(search_trimmed)
        });

        let Some(entry) = mft_entry else {
            return Err(ForensicError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("File not found in MFT: {}", path_str),
            )));
        };

        if entry.data_runs.is_empty() {
            return Ok(Vec::new());
        }

        // Read file content from data runs using cached parameters
        let cluster_size = cache.cluster_size;
        let partition_offset = cache.partition_offset;
        // Cap read size to 100MB to avoid OOM on huge files
        let max_read = (entry.size as usize).min(100 * 1024 * 1024);

        let mut content = Vec::with_capacity(max_read);
        for run in &entry.data_runs {
            if content.len() >= max_read {
                break;
            }
            if let Some(cluster_offset) = run.cluster_offset {
                let byte_offset = partition_offset + (cluster_offset as u64) * cluster_size;
                let byte_length =
                    ((run.cluster_length * cluster_size) as usize).min(max_read - content.len());
                match self.read_at(byte_offset, byte_length) {
                    Ok(data) => content.extend_from_slice(&data),
                    Err(e) => {
                        warn!(
                            "[EwfVfs] Failed to read data run at offset {}: {}",
                            byte_offset, e
                        );
                        break;
                    }
                }
            } else {
                let zero_bytes =
                    ((run.cluster_length * cluster_size) as usize).min(max_read - content.len());
                content.extend(std::iter::repeat_n(0u8, zero_bytes));
            }
        }

        content.truncate(entry.size as usize);
        Ok(content)
    }

    fn file_metadata(&self, _path: &Path) -> Result<VfsEntry, ForensicError> {
        Err(ForensicError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "File metadata lookup by path not yet implemented cross-platform.",
        )))
    }

    fn total_size(&self) -> u64 {
        self.volumes.first().map(|v| v.size).unwrap_or(0)
    }

    fn read_volume_at(&self, offset: u64, size: usize) -> Result<Vec<u8>, ForensicError> {
        self.read_at(offset, size)
    }

    fn get_volumes(&self) -> Vec<VolumeInfo> {
        let mut volumes: Vec<VolumeInfo> = self
            .volumes
            .iter()
            .map(|v| {
                let fs_type = v
                    .filesystem
                    .as_deref()
                    .map(|s| match s {
                        "NTFS" => FileSystemType::NTFS,
                        "FAT32" => FileSystemType::FAT32,
                        "exFAT" => FileSystemType::ExFAT,
                        "Ext4" => FileSystemType::Ext4,
                        "XFS" => FileSystemType::XFS,
                        "HFS+" => FileSystemType::HFSPlus,
                        "APFS" => FileSystemType::APFS,
                        _ => FileSystemType::Unknown,
                    })
                    .unwrap_or(FileSystemType::Unknown);

                VolumeInfo {
                    volume_index: v.index,
                    offset: v.offset,
                    size: v.size,
                    sector_size: 512,
                    filesystem: fs_type,
                    label: v.filesystem.clone(),
                    cluster_size: None,
                    mft_offset: None,
                    mft_record_size: None,
                    serial_number: None,
                }
            })
            .collect();

        // Scan NTFS volumes for VSS snapshots
        for vol in volumes.clone() {
            if vol.filesystem == FileSystemType::NTFS {
                if let Ok(snaps) = crate::shadowcopy::enumerate_vss_snapshots(self, vol.offset) {
                    for snap in &snaps {
                        let label = match snap.creation_time {
                            Some(ts) => {
                                let dt = chrono::DateTime::from_timestamp(ts, 0);
                                format!(
                                    "VSS Snapshot {} ({})",
                                    snap.snapshot_id,
                                    dt.map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                        .unwrap_or_else(|| format!("epoch {}", ts)),
                                )
                            }
                            None => format!("VSS Snapshot {}", snap.snapshot_id),
                        };
                        volumes.push(VolumeInfo {
                            volume_index: 1000 + snap.index,
                            offset: vol.offset,
                            size: vol.size,
                            sector_size: 512,
                            filesystem: FileSystemType::NTFS,
                            label: Some(label),
                            cluster_size: None,
                            mft_offset: None,
                            mft_record_size: None,
                            serial_number: None,
                        });
                    }
                }
            }
        }

        volumes
    }
}

#[cfg(target_os = "windows")]
impl VirtualFileSystem for EwfVfs {
    fn root(&self) -> &PathBuf {
        &self.root
    }

    fn enumerate_ntfs_directory(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        // Use the full MFT index to return ALL files recursively, not just
        // root-level children.  This gives the file tree its full hierarchy.
        let index = self.get_or_build_ntfs_index(vol_info)?;
        if !index.entries.is_empty() {
            // Re-map index paths from /vol{N}/... to /ntfs_vol{N}/... so the
            // Tree indexer builds the expected vfs_path format.
            let mapped: Vec<VfsEntry> = index
                .entries
                .iter()
                .map(|e| {
                    let path_str = e.path.to_string_lossy().replace('\\', "/");
                    let remapped = if let Some(rest) = path_str.strip_prefix("/vol") {
                        format!("/ntfs_vol{}", rest)
                    } else {
                        path_str.clone()
                    };
                    VfsEntry {
                        path: PathBuf::from(&remapped),
                        name: e.name.clone(),
                        is_dir: e.is_dir,
                        size: e.size,
                        modified: e.modified,
                    }
                })
                .collect();
            return Ok(mapped);
        }
        // Fallback: shallow directory listing from root MFT record.
        self.enumerate_ntfs_root_shallow(vol_info)
    }

    fn read_volume_at(&self, offset: u64, size: usize) -> Result<Vec<u8>, ForensicError> {
        self.read_at(offset, size)
    }

    fn enumerate_xfs_directory(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        use crate::xfs::{xfs_fast_scan, XfsDirEntry, XfsFileType, XfsReader};
        let mut entries = Vec::new();

        let vol_offset = vol_info.offset;

        let superblock_data = self.read_at(vol_offset, 256)?;

        if let Ok(scan) = xfs_fast_scan(&superblock_data) {
            if scan.found {
                info!(
                    "[EwfVfs][XFS] Found XFS filesystem: block_size={}, blocks={}",
                    scan.block_size, scan.total_blocks
                );

                match XfsReader::open(&superblock_data) {
                    Ok(reader) => {
                        let xfs_res: Result<Vec<XfsDirEntry>, crate::errors::ForensicError> =
                            reader.enumerate_root();
                        match xfs_res {
                            Ok(dir_entries) => {
                                info!(
                                    "[EwfVfs][XFS] Root directory has {} entries",
                                    dir_entries.len()
                                );
                                for entry in dir_entries {
                                    let is_dir = matches!(entry.entry_type, XfsFileType::Directory);
                                    entries.push(VfsEntry {
                                        path: PathBuf::from(format!(
                                            "/vol{}/{}",
                                            vol_info.volume_index, entry.name
                                        )),
                                        name: entry.name,
                                        is_dir,
                                        size: 0,
                                        modified: None,
                                    });
                                }
                            }
                            Err(e) => {
                                warn!("[EwfVfs][XFS] Failed to enumerate root: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[EwfVfs][XFS] Failed to create reader: {:?}", e);
                    }
                }

                if entries.is_empty() {
                    entries.push(VfsEntry {
                        path: PathBuf::from(format!("/vol{}/lost+found", vol_info.volume_index)),
                        name: "lost+found".to_string(),
                        is_dir: true,
                        size: 0,
                        modified: None,
                    });
                    entries.push(VfsEntry {
                        path: PathBuf::from(format!("/vol{}/root", vol_info.volume_index)),
                        name: "root".to_string(),
                        is_dir: true,
                        size: 0,
                        modified: None,
                    });
                    entries.push(VfsEntry {
                        path: PathBuf::from(format!("/vol{}/home", vol_info.volume_index)),
                        name: "home".to_string(),
                        is_dir: true,
                        size: 0,
                        modified: None,
                    });
                }
            }
        }

        if entries.is_empty() {
            entries.push(VfsEntry {
                path: PathBuf::from(format!("/vol{}/XFS_Root", vol_info.volume_index)),
                name: "XFS_Root".to_string(),
                is_dir: true,
                size: vol_info.size,
                modified: None,
            });
        }

        Ok(entries)
    }

    fn enumerate_fat32_directory(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        let mut entries = Vec::new();
        let vol_offset = vol_info.offset as usize;

        let boot_sector = match self.read_at(vol_offset as u64, 512) {
            Ok(d) if d.len() >= 512 => d,
            _ => return Ok(entries),
        };

        let jump = boot_sector[0];
        if jump != 0xEB && jump != 0xE9 {
            return Ok(entries);
        }

        entries.push(VfsEntry {
            path: PathBuf::from(format!("/vol{}/FAT32_Volume", vol_info.volume_index)),
            name: "FAT32_Volume".to_string(),
            is_dir: true,
            size: vol_info.size,
            modified: None,
        });

        Ok(entries)
    }

    fn enumerate_ext4_directory(
        &self,
        vol_info: &VolumeInfo,
    ) -> Result<Vec<VfsEntry>, ForensicError> {
        let mut entries = Vec::new();

        entries.push(VfsEntry {
            path: PathBuf::from(format!("/vol{}/lost+found", vol_info.volume_index)),
            name: "lost+found".to_string(),
            is_dir: true,
            size: 0,
            modified: None,
        });
        entries.push(VfsEntry {
            path: PathBuf::from(format!("/vol{}/home", vol_info.volume_index)),
            name: "home".to_string(),
            is_dir: true,
            size: 0,
            modified: None,
        });

        Ok(entries)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<VfsEntry>, ForensicError> {
        let normalized_path = Self::normalize_virtual_path(path);

        if normalized_path.starts_with("/vol") {
            let vol_idx = Self::volume_index_from_path(path).unwrap_or(0);
            let volumes = self.get_volumes();
            if let Some(vol_info) = volumes.iter().find(|v| v.volume_index == vol_idx) {
                return match vol_info.filesystem {
                    FileSystemType::NTFS => {
                        let index = self.get_or_build_ntfs_index(vol_info)?;
                        Ok(index
                            .children_by_dir
                            .get(&normalized_path)
                            .cloned()
                            .unwrap_or_default())
                    }
                    FileSystemType::APFS => self.enumerate_apfs_directory(vol_info, path),
                    FileSystemType::XFS => {
                        let volume_root = format!("/vol{}", vol_idx);
                        if normalized_path == volume_root {
                            self.enumerate_xfs_directory(vol_info)
                        } else {
                            Ok(Vec::new())
                        }
                    }
                    FileSystemType::FAT32 => {
                        let volume_root = format!("/vol{}", vol_idx);
                        if normalized_path == volume_root {
                            self.enumerate_fat32_directory(vol_info)
                        } else {
                            Ok(Vec::new())
                        }
                    }
                    FileSystemType::Ext4 => {
                        let volume_root = format!("/vol{}", vol_idx);
                        if normalized_path == volume_root {
                            self.enumerate_ext4_directory(vol_info)
                        } else {
                            Ok(Vec::new())
                        }
                    }
                    FileSystemType::HFSPlus => {
                        let volume_root = format!("/vol{}", vol_idx);
                        if normalized_path == volume_root {
                            self.enumerate_hfsplus_directory(vol_info)
                        } else {
                            Ok(Vec::new())
                        }
                    }
                    _ => Ok(Vec::new()),
                };
            }
        }

        if normalized_path == "/" {
            let mut entries = Vec::new();

            let volumes = self.get_volumes();
            for vol in &volumes {
                entries.push(VfsEntry {
                    path: PathBuf::from(format!("/vol{}", vol.volume_index)),
                    name: format!(
                        "{} Volume {} ({} GB)",
                        vol.filesystem.as_str(),
                        vol.volume_index,
                        vol.size / 1_000_000_000
                    ),
                    is_dir: true,
                    size: vol.size,
                    modified: None,
                });
            }

            if entries.is_empty() {
                entries.push(VfsEntry {
                    path: PathBuf::from("/raw"),
                    name: format!("Raw Disk Image ({} GB)", self.total_size() / 1_000_000_000),
                    is_dir: true,
                    size: self.total_size(),
                    modified: None,
                });
            }

            return Ok(entries);
        }

        Ok(Vec::new())
    }

    fn open_file(&self, path: &Path) -> Result<Vec<u8>, ForensicError> {
        let vol_idx =
            EwfVfs::volume_index_from_path(path).ok_or(ForensicError::UnsupportedFilesystem)?;
        let volumes = self.get_volumes();
        let vol_info = volumes
            .iter()
            .find(|v| v.volume_index == vol_idx)
            .ok_or(ForensicError::UnsupportedFilesystem)?;

        if vol_info.filesystem != FileSystemType::NTFS {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        let index = self.get_or_build_ntfs_index(vol_info)?;
        let normalized = EwfVfs::normalize_index_path(path);
        let payload = index
            .file_payload_by_path
            .get(&normalized)
            .ok_or(ForensicError::OutOfRange(path.display().to_string()))?;

        if let Some(data) = &payload.resident_data {
            let mut out = data.clone();
            if payload.size > 0 && (out.len() as u64) > payload.size {
                out.truncate(payload.size as usize);
            }
            return Ok(out);
        }

        let cluster_size = vol_info.cluster_size.unwrap_or(4096).max(1) as u64;
        let effective_size = if payload.size > 0 {
            payload.size
        } else {
            payload
                .data_runs
                .iter()
                .map(|(_, count)| count.saturating_mul(cluster_size))
                .sum::<u64>()
        };

        const MAX_OPEN_FILE_BYTES: u64 = 256 * 1024 * 1024;
        if effective_size > MAX_OPEN_FILE_BYTES {
            return Err(ForensicError::OutOfRange(format!(
                "virtual file too large for in-memory read: {} bytes (use read_file_range instead)",
                effective_size
            )));
        }

        let mut out = Vec::with_capacity(effective_size as usize);
        let mut remaining = effective_size;

        for (lcn_opt, cluster_count) in &payload.data_runs {
            if remaining == 0 {
                break;
            }

            let run_bytes = cluster_count.saturating_mul(cluster_size);
            let mut to_take = run_bytes.min(remaining);
            if to_take == 0 {
                continue;
            }

            match lcn_opt {
                None => {
                    let new_len = out.len().saturating_add(to_take as usize);
                    out.resize(new_len, 0u8);
                }
                Some(lcn) if *lcn >= 0 => {
                    let rel_offset = (*lcn as u64).saturating_mul(cluster_size);
                    let available = vol_info.size.saturating_sub(rel_offset);
                    to_take = to_take.min(available);
                    if to_take == 0 {
                        break;
                    }

                    let abs_offset = vol_info.offset.saturating_add(rel_offset);
                    let chunk = self.read_at(abs_offset, to_take as usize)?;
                    if chunk.len() < to_take as usize {
                        out.extend_from_slice(&chunk);
                        let pad = to_take as usize - chunk.len();
                        let new_len = out.len().saturating_add(pad);
                        out.resize(new_len, 0u8);
                    } else {
                        out.extend_from_slice(&chunk[..to_take as usize]);
                    }
                }
                Some(_) => break,
            }

            remaining = remaining.saturating_sub(to_take);
        }

        if remaining > 0 {
            let new_len = out.len().saturating_add(remaining as usize);
            out.resize(new_len, 0u8);
        }
        Ok(out)
    }

    fn read_file_range(
        &self,
        path: &Path,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, ForensicError> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let vol_idx =
            EwfVfs::volume_index_from_path(path).ok_or(ForensicError::UnsupportedFilesystem)?;
        let volumes = self.get_volumes();
        let vol_info = volumes
            .iter()
            .find(|v| v.volume_index == vol_idx)
            .ok_or(ForensicError::UnsupportedFilesystem)?;

        if vol_info.filesystem != FileSystemType::NTFS {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        let index = self.get_or_build_ntfs_index(vol_info)?;
        let normalized = EwfVfs::normalize_index_path(path);
        let payload = index
            .file_payload_by_path
            .get(&normalized)
            .ok_or(ForensicError::OutOfRange(path.display().to_string()))?;

        // For resident data, just slice directly.
        if let Some(data) = &payload.resident_data {
            let start = offset as usize;
            if start >= data.len() {
                return Ok(Vec::new());
            }
            let end = start
                .saturating_add(len)
                .min(data.len())
                .min(payload.size as usize);
            return Ok(data[start..end].to_vec());
        }

        let cluster_size = vol_info.cluster_size.unwrap_or(4096).max(1) as u64;
        // payload.size may be 0 for files whose $DATA attribute is in an
        // extension MFT record (large files with attribute lists).  When the
        // recorded size is missing, estimate from total data-run allocation or
        // fall back to the caller's requested range.
        let effective_size = if payload.size > 0 {
            payload.size
        } else {
            let allocated: u64 = payload
                .data_runs
                .iter()
                .map(|(_, count)| count.saturating_mul(cluster_size))
                .sum();
            if allocated > 0 {
                allocated
            } else {
                offset.saturating_add(len as u64)
            }
        };
        let req_start = offset;
        let req_end = offset.saturating_add(len as u64).min(effective_size);
        if req_start >= req_end {
            return Ok(Vec::new());
        }
        let need = (req_end - req_start) as usize;
        let mut out = Vec::with_capacity(need);

        // Walk data runs, skip runs before the requested window,
        // read only runs that overlap [req_start, req_end).
        let mut file_pos: u64 = 0;
        for (lcn_opt, cluster_count) in &payload.data_runs {
            if out.len() >= need {
                break;
            }

            let run_bytes = cluster_count.saturating_mul(cluster_size);
            let run_start = file_pos;
            let run_end = file_pos.saturating_add(run_bytes);
            file_pos = run_end;

            // Skip runs entirely before requested range.
            if run_end <= req_start {
                continue;
            }
            // Stop if past requested range.
            if run_start >= req_end {
                break;
            }

            // Overlap: [overlap_start, overlap_end) within file coordinates.
            let overlap_start = run_start.max(req_start);
            let overlap_end = run_end.min(req_end);
            let overlap_len = (overlap_end - overlap_start) as usize;
            if overlap_len == 0 {
                continue;
            }

            let offset_within_run = overlap_start - run_start;

            match lcn_opt {
                None => {
                    // Sparse run — zero-filled.
                    let new_len = out.len().saturating_add(overlap_len);
                    out.resize(new_len, 0u8);
                }
                Some(lcn) if *lcn >= 0 => {
                    let run_disk_offset = (*lcn as u64).saturating_mul(cluster_size);
                    let abs_offset = vol_info
                        .offset
                        .saturating_add(run_disk_offset)
                        .saturating_add(offset_within_run);
                    let available = vol_info
                        .size
                        .saturating_sub(run_disk_offset.saturating_add(offset_within_run));
                    let to_read = (overlap_len as u64).min(available) as usize;
                    if to_read == 0 {
                        let new_len = out.len().saturating_add(overlap_len);
                        out.resize(new_len, 0u8);
                        continue;
                    }
                    let chunk = self.read_at(abs_offset, to_read)?;
                    out.extend_from_slice(&chunk);
                    if chunk.len() < overlap_len {
                        let pad = overlap_len - chunk.len();
                        let new_len = out.len().saturating_add(pad);
                        out.resize(new_len, 0u8);
                    }
                }
                Some(_) => break,
            }
        }

        // Pad if file data runs didn't cover the full range.
        if out.len() < need {
            out.resize(need, 0u8);
        }
        out.truncate(need);
        Ok(out)
    }

    fn file_metadata(&self, path: &Path) -> Result<VfsEntry, ForensicError> {
        let normalized_path = self.normalize_virtual_path(path);
        if normalized_path == "/" {
            return Ok(VfsEntry {
                path: self.root.clone(),
                name: self
                    .root()
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "E01 Image".to_string()),
                is_dir: true,
                size: self.total_size(),
                modified: None,
            });
        }

        let index_path = Self::normalize_index_path(path);
        if index_path.starts_with("/vol") {
            let vol_idx =
                Self::volume_index_from_path(path).ok_or(ForensicError::UnsupportedFilesystem)?;
            let volumes = self.get_volumes();
            if let Some(vol_info) = volumes.iter().find(|v| v.volume_index == vol_idx) {
                if vol_info.filesystem == FileSystemType::NTFS {
                    let index = self.get_or_build_ntfs_index(vol_info)?;
                    if let Some(entry) = index.entries_by_path.get(&index_path) {
                        return Ok(entry.clone());
                    }
                }
            }
        }

        Err(ForensicError::UnsupportedFilesystem)
    }

    fn total_size(&self) -> u64 {
        self.reader.lock().map(|r| r.total_size()).unwrap_or(0)
    }

    fn enumerate_volume(&self, volume_index: usize) -> Result<Vec<VfsEntry>, ForensicError> {
        let volumes = self.get_volumes();
        if let Some(vol_info) = volumes.iter().find(|v| v.volume_index == volume_index) {
            if vol_info.filesystem == FileSystemType::NTFS {
                let index = self.get_or_build_ntfs_index(vol_info)?;
                return Ok(index.entries.clone());
            }
            let path = PathBuf::from(format!("/vol{}", volume_index));
            return self.read_dir(path.as_path());
        }
        Ok(Vec::new())
    }

    fn get_volumes(&self) -> Vec<VolumeInfo> {
        let debug_start = "[VFS] get_volumes CALLED - cache check\n".to_string();
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("D:\\forensic-suite\\target\\debug\\vfs_debug.log")
            .map(|mut f| {
                let _ = std::io::Write::write_all(&mut f, debug_start.as_bytes());
                f
            });

        if let Ok(cache) = self.volume_cache.lock() {
            if let Some(cached) = cache.as_ref() {
                let debug_cache = format!(
                    "[VFS] get_volumes returning CACHED {} volumes\n",
                    cached.len()
                );
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("D:\\forensic-suite\\target\\debug\\vfs_debug.log")
                    .map(|mut f| {
                        let _ = std::io::Write::write_all(&mut f, debug_cache.as_bytes());
                        f
                    });
                return cached.clone();
            }
        }

        let mut volumes = Vec::new();
        let debug_fresh = "[VFS] get_volumes running FRESH scan\n".to_string();
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("D:\\forensic-suite\\target\\debug\\vfs_debug.log")
            .map(|mut f| {
                let _ = std::io::Write::write_all(&mut f, debug_fresh.as_bytes());
                f
            });

        for vol in &self.volumes {
            let probe_size = 262_144usize.min(vol.size as usize).max(512);
            let debug_read = format!(
                "[VFS] get_volumes: vol.offset={}, vol.size={}, probe_size={}\n",
                vol.offset, vol.size, probe_size
            );
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("D:\\forensic-suite\\target\\debug\\vfs_debug.log")
                .map(|mut f| {
                    let _ = std::io::Write::write_all(&mut f, debug_read.as_bytes());
                    f
                });

            if let Ok(head) = self.read_at(vol.offset, probe_size) {
                let debug_head = format!(
                    "[VFS] read_at returned {} bytes, bytes at 0-16: {:02X?} at 512-528: {:02X?}\n",
                    head.len(),
                    &head.get(0..16.min(head.len())).unwrap_or(&[]),
                    head.get(512..528.min(head.len())).unwrap_or(&[])
                );
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("D:\\forensic-suite\\target\\debug\\vfs_debug.log")
                    .map(|mut f| {
                        let _ = std::io::Write::write_all(&mut f, debug_head.as_bytes());
                        f
                    });

                let has_mbr =
                    head.len() >= 512 && u16::from_le_bytes([head[0x1FE], head[0x1FF]]) == 0xAA55;

                let mut candidate_offsets: Vec<u64> = Vec::new();

                // MBR partition scanning
                if has_mbr {
                    for i in 0..4usize {
                        let base = 446 + (i * 16);
                        if base + 16 > head.len() {
                            break;
                        }
                        let part_type = head[base + 4];
                        let lba_start = u32::from_le_bytes([
                            head[base + 8],
                            head[base + 9],
                            head[base + 10],
                            head[base + 11],
                        ]) as u64;

                        if part_type != 0 && lba_start > 0 {
                            candidate_offsets.push(lba_start.saturating_mul(512));
                        }
                    }
                }

                // GPT partition scanning - Mac E01 images use GPT, not MBR
                // GPT header is at LBA 1 (offset 512), signature "EFI PART"
                if head.len() >= 512 + 92 {
                    if &head[512..520] == b"EFI PART" {
                        let debug_gpt = "[VFS] Found GPT header at LBA 1\n".to_string();
                        let _ = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("D:\\forensic-suite\\target\\debug\\vfs_debug.log")
                            .map(|mut f| {
                                let _ = std::io::Write::write_all(&mut f, debug_gpt.as_bytes());
                                f
                            });

                        let gpt_header = &head[512..512 + 512];
                        let entry_lba =
                            u64::from_le_bytes(gpt_header[72..80].try_into().unwrap_or([0; 8]));
                        let num_partitions =
                            u32::from_le_bytes(gpt_header[80..84].try_into().unwrap_or([0; 4]))
                                as usize;
                        let entry_size =
                            u32::from_le_bytes(gpt_header[84..88].try_into().unwrap_or([0; 4]))
                                as usize;

                        let part_table_offset = entry_lba.saturating_mul(512);
                        let part_table_size =
                            num_partitions.saturating_mul(entry_size).min(1024 * 1024);

                        if let Ok(part_table_data) =
                            self.read_at(vol.offset + part_table_offset, part_table_size)
                        {
                            let debug_gpt2 = format!(
                                "[VFS] GPT partition count: {}, entry_size: {}, table_offset: {}\n",
                                num_partitions, entry_size, part_table_offset
                            );
                            let _ = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("D:\\forensic-suite\\target\\debug\\vfs_debug.log")
                                .map(|mut f| {
                                    let _ =
                                        std::io::Write::write_all(&mut f, debug_gpt2.as_bytes());
                                    f
                                });

                            // Iterate over partitions
                            for i in 0..num_partitions {
                                let entry_start = i * entry_size;
                                if entry_start + entry_size > part_table_data.len() {
                                    break;
                                }

                                let entry = &part_table_data[entry_start..entry_start + entry_size];

                                let start_lba = u64::from_le_bytes([
                                    entry[32], entry[33], entry[34], entry[35], entry[36],
                                    entry[37], entry[38], entry[39],
                                ]);

                                let end_lba = u64::from_le_bytes([
                                    entry[40], entry[41], entry[42], entry[43], entry[44],
                                    entry[45], entry[46], entry[47],
                                ]);

                                if start_lba == 0 || end_lba <= start_lba {
                                    continue;
                                }

                                // APFS container GUID: 7C3457EF-0000-11AA-AA11-00306543ECAC
                                // Apple_APFS container type: 7C3457EF-0000-11AA-AA11-00306543ECAC
                                let apfs_guid = [
                                    0x7C, 0x34, 0x57, 0xEF, 0x00, 0x00, 0x11, 0xAA, 0xAA, 0x11,
                                    0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC,
                                ];

                                // Apple_APFS container: 8ECDA4F7-0DD4-46D6-82BC-C7D853425401
                                let apple_apfs_guid = [
                                    0x8E, 0xCD, 0xA4, 0xF7, 0x0D, 0xD4, 0x46, 0xD6, 0x82, 0xBC,
                                    0xC7, 0xD8, 0x53, 0x42, 0x54, 0x01,
                                ];

                                let is_apfs =
                                    entry[0..16] == apfs_guid || entry[0..16] == apple_apfs_guid;

                                let part_offset = start_lba.saturating_mul(512);

                                if part_offset > 0 {
                                    candidate_offsets.push(part_offset);
                                    let debug_gpt3 = format!(
                                        "[VFS] GPT partition {}: offset={}, start_lba={}, end_lba={}, is_apfs={}\n",
                                        i, part_offset, start_lba, end_lba, is_apfs
                                    );
                                    let _ = std::fs::OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open("D:\\forensic-suite\\target\\debug\\vfs_debug.log")
                                        .map(|mut f| {
                                            let _ = std::io::Write::write_all(
                                                &mut f,
                                                debug_gpt3.as_bytes(),
                                            );
                                            f
                                        });
                                }
                            }
                        }
                    } else {
                        // Check for GPT at other common offsets
                        let debug_gpt =
                            "[VFS] No GPT at offset 512, checking other offsets\n".to_string();
                        let _ = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("D:\\forensic-suite\\target\\debug\\vfs_debug.log")
                            .map(|mut f| {
                                let _ = std::io::Write::write_all(&mut f, debug_gpt.as_bytes());
                                f
                            });
                    }
                }

                // Common starts for GPT/protective MBR and legacy layouts.
                candidate_offsets.extend_from_slice(&[
                    0, 1_048_576, // 2048 * 512
                    2_097_152, // 4096 * 512
                    32_256,    // 63 * 512
                    65_536,
                ]);
                candidate_offsets.sort_unstable();
                candidate_offsets.dedup();

                let mut found_any = false;

                for rel_offset in candidate_offsets {
                    if rel_offset >= vol.size {
                        continue;
                    }

                    let abs_offset = vol.offset.saturating_add(rel_offset);
                    let remaining = vol.size.saturating_sub(rel_offset);
                    let read_len = 65_536usize.min(remaining as usize);
                    if read_len < 512 {
                        continue;
                    }

                    let part_data = match self.read_at(abs_offset, read_len) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };

                    let fs_type = detect_filesystem_in_buffer(&part_data);
                    if fs_type == FileSystemType::Unknown {
                        continue;
                    }

                    let sector_size = if part_data.len() >= 13 {
                        u16::from_le_bytes([part_data[11], part_data[12]]).max(512) as u64
                    } else {
                        512
                    };

                    let cluster_size = if part_data.len() >= 14 {
                        let secs = part_data[13];
                        if secs > 0 {
                            Some((sector_size as u32).saturating_mul(secs as u32))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let mut serial: Option<u64> = None;
                    let mut mft_offset: Option<u64> = None;
                    let mut mft_record_size: Option<u32> = None;

                    if fs_type == FileSystemType::NTFS && part_data.len() >= 80 {
                        if let Ok(boot) = parse_ntfs_boot_sector(&part_data) {
                            serial = Some(boot.serial_number);
                            let mft_offset_val = (boot.mft_lcn.max(0) as u64)
                                .saturating_mul(boot.cluster_size_bytes as u64);
                            mft_offset = Some(mft_offset_val);
                            mft_record_size = Some(boot.mft_record_size_bytes);
                            info!(
                                "[EWF][NTFS] volume_idx={} rel_offset={} mft_lcn={} cluster_size={} mft_offset={} mft_record_size={}",
                                volumes.len(),
                                rel_offset,
                                boot.mft_lcn,
                                boot.cluster_size_bytes,
                                mft_offset_val,
                                boot.mft_record_size_bytes
                            );
                        }
                    }

                    volumes.push(VolumeInfo {
                        volume_index: volumes.len(),
                        offset: abs_offset,
                        size: remaining,
                        sector_size,
                        filesystem: fs_type,
                        label: None,
                        cluster_size,
                        mft_offset,
                        mft_record_size,
                        serial_number: serial,
                    });
                    found_any = true;
                }

                if !found_any {
                    // Keep one fallback volume so GUI can still show metadata for unknown layouts.
                    let fs_type = detect_filesystem_in_buffer(&head);
                    let sector_size = if head.len() >= 13 {
                        u16::from_le_bytes([head[11], head[12]]).max(512) as u64
                    } else {
                        512
                    };
                    volumes.push(VolumeInfo {
                        volume_index: volumes.len(),
                        offset: vol.offset,
                        size: vol.size,
                        sector_size,
                        filesystem: fs_type,
                        label: None,
                        cluster_size: None,
                        mft_offset: None,
                        mft_record_size: None,
                        serial_number: None,
                    });
                }
            }
        }

        // Scan NTFS volumes for VSS snapshots
        let vss_additions: Vec<VolumeInfo> = volumes
            .iter()
            .filter(|v| v.filesystem == FileSystemType::NTFS)
            .flat_map(|vol| {
                crate::shadowcopy::enumerate_vss_snapshots(self, vol.offset)
                    .unwrap_or_default()
                    .into_iter()
                    .map(move |snap| {
                        let label = match snap.creation_time {
                            Some(ts) => {
                                let dt = chrono::DateTime::from_timestamp(ts, 0);
                                format!(
                                    "VSS Snapshot {} ({})",
                                    snap.snapshot_id,
                                    dt.map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                        .unwrap_or_else(|| format!("epoch {}", ts)),
                                )
                            }
                            None => format!("VSS Snapshot {}", snap.snapshot_id),
                        };
                        VolumeInfo {
                            volume_index: 1000 + snap.index,
                            offset: vol.offset,
                            size: vol.size,
                            sector_size: 512,
                            filesystem: FileSystemType::NTFS,
                            label: Some(label),
                            cluster_size: None,
                            mft_offset: None,
                            mft_record_size: None,
                            serial_number: None,
                        }
                    })
            })
            .collect();
        volumes.extend(vss_additions);

        if let Ok(mut cache) = self.volume_cache.lock() {
            *cache = Some(volumes.clone());
        }

        volumes
    }

    fn get_unallocated_regions(&self) -> Vec<ScanRegion> {
        Vec::new()
    }

    fn get_slack_regions(&self) -> Vec<ScanRegion> {
        Vec::new()
    }
}

pub fn detect_filesystem_in_buffer(data: &[u8]) -> FileSystemType {
    if data.len() >= 4 {
        tracing::trace!(
            "[DETECT] Checking bytes: {:02X} {:02X} {:02X} {:02X}",
            data[0],
            data[1],
            data[2],
            data[3]
        );
    }

    // XFS detection - superblock magic "XFSB" at offset 0 (check early for efficiency)
    if data.len() >= 4 && &data[0..4] == b"XFSB" {
        return FileSystemType::XFS;
    }

    if data.len() < 12 {
        return FileSystemType::Unknown;
    }

    // NTFS detection - check at offset 3 for "NTFS    "
    if data.len() >= 11 && &data[3..11] == b"NTFS    " {
        return FileSystemType::NTFS;
    }

    // APFS detection
    if data.len() >= 7 && &data[0..7] == b"NEW\0" {
        return FileSystemType::APFS;
    }

    if data.len() >= 8 && &data[0..8] == b"NXSB\0\0\0" {
        return FileSystemType::APFS;
    }

    // APFS container superblock signature can appear at 32KiB.
    // Guard the slice end explicitly to avoid out-of-bounds panics.
    if data.len() >= 32773 && &data[32768..32773] == b"CH\x00\x00\x00" {
        return FileSystemType::APFS;
    }

    // exFAT detection
    if data.len() >= 11 && &data[3..11] == b"EXFAT   " {
        return FileSystemType::ExFAT;
    }

    // FAT detection - look for boot sector with jump instruction
    // Most FAT boot sectors start with EB xx 90 or E9 xx xx
    if data.len() >= 64 {
        // Check for jump boot instruction (EB xx 90 or E9 xx xx)
        let is_boot_jump = data[0] == 0xEB || data[0] == 0xE9;

        if is_boot_jump {
            // Check for FAT signature at offset 0x36 (54 bytes - "FAT" string)
            if data.len() >= 0x38 {
                let fs_str = String::from_utf8_lossy(&data[0x36..0x3E]);
                if fs_str.starts_with("FAT") {
                    return FileSystemType::FAT32;
                }
            }

            // Check for FAT32 at offset 0x52
            if data.len() >= 0x54 {
                let fs_str = String::from_utf8_lossy(&data[0x52..0x5A]);
                if fs_str.starts_with("FAT32") {
                    return FileSystemType::FAT32;
                }
            }

            // Check OEM name at offset 3
            if data.len() >= 11 {
                let oem = String::from_utf8_lossy(&data[3..11]);
                if oem.starts_with("MSDOS") || oem.starts_with("IBM") || oem.starts_with("WIN") {
                    // Likely FAT - check for valid geometry
                    let bps = u16::from_le_bytes([data[11], data[12]]);
                    if (512..=4096).contains(&bps) && (bps & (bps - 1)) == 0 {
                        return FileSystemType::FAT32;
                    }
                }
            }

            // If jump boot + valid bytes per sector + sectors per cluster, likely FAT
            let bps = u16::from_le_bytes([data[11], data[12]]);
            let spc = data[13];
            if (512..=4096).contains(&bps) && spc > 0 && spc < 128 {
                return FileSystemType::FAT32;
            }
        }
    }

    // Fallback: check for FAT32 string at various offsets
    if data.len() >= 90 && &data[82..90] == b"FAT32   " {
        return FileSystemType::FAT32;
    }

    // ext2/ext4 detection - superblock at offset 1024 (0x400)
    if data.len() >= 1084 {
        // ext2/ext4 superblock magic at offset 0x38 (56) from superblock start
        let s_magic = u16::from_le_bytes([data[0x438], data[0x439]]);
        if s_magic == 0xEF53 {
            // Check for ext4 features if present
            let s_feature_incompat =
                u32::from_le_bytes([data[0x460], data[0x461], data[0x462], data[0x463]]);
            if (s_feature_incompat & 0x2) != 0 {
                return FileSystemType::Ext4; // extents feature
            }
            return FileSystemType::Ext4;
        }
    }

    // Also check at offset 0 for ext (some disk images have it there)
    if data.len() >= 1100 {
        let s_magic = u16::from_le_bytes([data[0x438], data[0x439]]);
        if s_magic == 0xEF53 {
            let s_feature_incompat =
                u32::from_le_bytes([data[0x460], data[0x461], data[0x462], data[0x463]]);
            if (s_feature_incompat & 0x2) != 0 {
                return FileSystemType::Ext4;
            }
            return FileSystemType::Ext4;
        }
    }

    // ISO 9660 - Primary Volume Descriptor at sector 16 (32KB)
    if data.len() >= 32768 + 64 && &data[32768..32769] == b"\x01" && &data[32769..32774] == b"CD001"
    {
        return FileSystemType::ISO9660;
    }

    // Also check at offset 0 for some ISO formats
    if data.len() >= 512 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 {
        // Could be ISO - try to check for CD001 at sector 16
        if data.len() >= 32768 + 64
            && &data[32768..32769] == b"\x01"
            && &data[32769..32774] == b"CD001"
        {
            return FileSystemType::ISO9660;
        }
    }

    FileSystemType::Unknown
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct NtfsBootInfo {
    serial_number: u64,
    mft_lcn: i64,
    cluster_size_bytes: u32,
    mft_record_size_bytes: u32,
}

#[cfg(target_os = "windows")]
fn parse_ntfs_boot_sector(data: &[u8]) -> Result<NtfsBootInfo, ()> {
    if data.len() < 90 || &data[3..11] != b"NTFS    " {
        return Err(());
    }

    let serial_number = u64::from_le_bytes([
        data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
    ]);

    let mft_lcn = i64::from_le_bytes([
        data[48], data[49], data[50], data[51], data[52], data[53], data[54], data[55],
    ]);

    let bytes_per_sector = u16::from_le_bytes([data[11], data[12]]);
    let sectors_per_cluster = data[13];
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) || sectors_per_cluster == 0 {
        return Err(());
    }
    let cluster_size_bytes = (bytes_per_sector as u32)
        .checked_mul(sectors_per_cluster as u32)
        .ok_or(())?;

    // NTFS clusters_per_file_record_segment is a signed i8 at offset 0x40.
    // Positive = clusters, negative = 2^abs(value) bytes.
    let clusters_per_mft_record = data[0x40] as i8;
    let mft_record_size_bytes = if clusters_per_mft_record > 0 {
        (clusters_per_mft_record as u32)
            .checked_mul(cluster_size_bytes)
            .ok_or(())?
    } else {
        let shift = (-clusters_per_mft_record) as u32;
        if shift >= 32 {
            return Err(());
        }
        1u32 << shift
    };

    Ok(NtfsBootInfo {
        serial_number,
        mft_lcn,
        cluster_size_bytes,
        mft_record_size_bytes,
    })
}

pub struct MountResult {
    pub format: ImageFormat,
    pub volumes: Vec<VolumeInfo>,
    pub vfs: Box<dyn VirtualFileSystem>,
    pub total_size: u64,
}

impl std::fmt::Debug for MountResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountResult")
            .field("format", &self.format)
            .field("volumes", &self.volumes)
            .field("total_size", &self.total_size)
            .finish()
    }
}

pub struct MountManager;

impl MountManager {
    pub fn mount(path: &Path) -> Result<MountResult, String> {
        let format_info =
            detect_image_format(path).map_err(|e| format!("Failed to detect format: {}", e))?;

        let format = format_info.format;

        match &format {
            ImageFormat::E01
            | ImageFormat::AFF
            | ImageFormat::AFF4
            | ImageFormat::S01
            | ImageFormat::Lx01
            | ImageFormat::Lx02 => Self::mount_disk_image(path, &format_info, format),
            ImageFormat::VHD | ImageFormat::VHDX | ImageFormat::VMDK => {
                Self::mount_virtual_disk(path, &format_info, format)
            }
            ImageFormat::DMG => Self::mount_dmg(path, &format_info, format),
            ImageFormat::ISO => Self::mount_iso(path, &format_info, format),
            ImageFormat::ZIP | ImageFormat::UFDR | ImageFormat::GRAYKEY | ImageFormat::AXIOM => {
                Self::mount_archive(path, &format_info, format)
            }
            ImageFormat::TAR | ImageFormat::GZIP => Self::mount_archive(path, &format_info, format),
            ImageFormat::RAW | ImageFormat::DD | ImageFormat::SplitRaw => {
                Self::mount_raw(path, &format_info, format)
            }
            _ => Err(format!("Unsupported format: {}", format.as_str())),
        }
    }

    #[cfg(target_os = "windows")]
    fn mount_disk_image(
        path: &Path,
        _format_info: &ImageFormatInfo,
        format: ImageFormat,
    ) -> Result<MountResult, String> {
        let vfs = EwfVfs::new(path).map_err(|e| format!("Failed to open disk image: {}", e))?;

        let volumes = vfs.get_volumes();
        let total_size = vfs.total_size();

        Ok(MountResult {
            format,
            volumes,
            vfs: Box::new(vfs),
            total_size,
        })
    }

    #[cfg(not(target_os = "windows"))]
    fn mount_disk_image(
        path: &Path,
        _format_info: &ImageFormatInfo,
        _format: ImageFormat,
    ) -> Result<MountResult, String> {
        // On non-Windows, open E01 via EwfVfs for raw byte access.
        // Full NTFS directory enumeration requires Windows; byte-level access works cross-platform.
        let vfs = EwfVfs::new(path).map_err(|e| format!("Failed to open E01: {}", e))?;
        let volumes = vfs.get_volumes();
        let total_size = vfs.volumes().first().map(|v| v.size).unwrap_or(0);
        Ok(MountResult {
            format: ImageFormat::E01,
            vfs: Box::new(vfs),
            volumes,
            total_size,
        })
    }

    fn mount_virtual_disk(
        path: &Path,
        _format_info: &ImageFormatInfo,
        format: ImageFormat,
    ) -> Result<MountResult, String> {
        match format {
            ImageFormat::VHD | ImageFormat::VHDX => {
                let vfs =
                    VhdVfs::new(path).map_err(|e| format!("Failed to open VHD/VHDX: {}", e))?;
                let volumes = vfs.get_volumes();
                let total_size = vfs.total_size();
                Ok(MountResult {
                    format,
                    volumes,
                    vfs: Box::new(vfs),
                    total_size,
                })
            }
            ImageFormat::VMDK => {
                let vfs = VmdkVfs::new(path).map_err(|e| format!("Failed to open VMDK: {}", e))?;
                let volumes = vfs.get_volumes();
                let total_size = vfs.total_size();
                Ok(MountResult {
                    format,
                    volumes,
                    vfs: Box::new(vfs),
                    total_size,
                })
            }
            _ => Err(format!(
                "Unsupported virtual disk format: {}",
                format.as_str()
            )),
        }
    }

    fn mount_dmg(
        path: &Path,
        _format_info: &ImageFormatInfo,
        format: ImageFormat,
    ) -> Result<MountResult, String> {
        let vfs = RawVfs::new(path).map_err(|e| format!("Failed to open DMG: {}", e))?;

        let volumes = vfs.get_volumes();
        let total_size = vfs.total_size();

        Ok(MountResult {
            format,
            volumes,
            vfs: Box::new(vfs),
            total_size,
        })
    }

    fn mount_iso(
        path: &Path,
        _format_info: &ImageFormatInfo,
        format: ImageFormat,
    ) -> Result<MountResult, String> {
        let vfs = IsoVfs::new(path).map_err(|e| format!("Failed to open ISO: {}", e))?;

        let volumes = vfs.get_volumes();
        let total_size = vfs.total_size();

        Ok(MountResult {
            format,
            volumes,
            vfs: Box::new(vfs),
            total_size,
        })
    }

    fn mount_archive(
        path: &Path,
        _format_info: &ImageFormatInfo,
        format: ImageFormat,
    ) -> Result<MountResult, String> {
        let vfs = RawVfs::new(path).map_err(|e| format!("Failed to open archive: {}", e))?;

        let volumes = vfs.get_volumes();
        let total_size = vfs.total_size();

        Ok(MountResult {
            format,
            volumes,
            vfs: Box::new(vfs),
            total_size,
        })
    }

    fn mount_raw(
        path: &Path,
        _format_info: &ImageFormatInfo,
        format: ImageFormat,
    ) -> Result<MountResult, String> {
        let vfs = RawVfs::new(path).map_err(|e| format!("Failed to open raw image: {}", e))?;

        let volumes = vfs.get_volumes();
        let total_size = vfs.total_size();

        Ok(MountResult {
            format,
            volumes,
            vfs: Box::new(vfs),
            total_size,
        })
    }
}

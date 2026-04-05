use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

pub fn open_vmdk(path: &Path) -> Result<VmdkContainer, ForensicError> {
    VmdkContainer::open(path)
}

#[derive(Debug, Clone)]
pub struct VmdkContainer {
    pub path: PathBuf,
    pub descriptor: VmdkDescriptor,
    pub extent_count: u32,
    pub size: u64,
    pub sparse_extents: Vec<Option<VmdkSparseMetadata>>,
}

#[derive(Debug, Clone, Default)]
pub struct VmdkDescriptor {
    pub version: String,
    pub cid: u32,
    pub parent_cid: u32,
    pub create_type: String,
    pub extents: Vec<VmdkExtent>,
}

#[derive(Debug, Clone)]
pub struct VmdkExtent {
    pub path: String,
    pub extent_type: VmdkExtentType,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VmdkExtentType {
    Flat,
    Sparse,
    VmfsSparse,
    VmfsFlat,
    VmfsRDM,
    VmfsRDMV,
}

#[derive(Debug, Clone)]
pub struct VmdkSparseMetadata {
    pub capacity: u64,
    pub grain_size: u64,
    pub gd_offset: u64,
    pub num_gtes_per_gte: u32,
    pub gd: Vec<u32>,
}

impl VmdkContainer {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;

        let mut buf = [0u8; 1024];
        let n = read_at(&file, 0, &mut buf).map_err(ForensicError::Io)?;
        if n == 0 {
            return Err(ForensicError::InvalidImageFormat);
        }

        let magic = if n >= 4 { &buf[0..4] } else { b"" };
        let is_sparse = magic == b"KDMV";

        let mut descriptor = VmdkDescriptor::default();
        let mut size = 0;

        if is_sparse {
            let desc_offset = u64::from_le_bytes(buf[32..40].try_into().unwrap_or([0; 8]))
                .checked_mul(512)
                .unwrap_or(0);
            if desc_offset > 0 {
                descriptor = Self::parse_descriptor(&file, desc_offset)?;
            } else {
                // Monolithic sparse without descriptor embedded at 536? Try to find it or parse a virtual extent
                descriptor.extents.push(VmdkExtent {
                    path: path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    extent_type: VmdkExtentType::Sparse,
                    offset: 0,
                    size: u64::from_le_bytes(buf[12..20].try_into().unwrap_or([0; 8])) * 512,
                });
            }
        } else {
            descriptor = Self::parse_descriptor(&file, 0)?;
        }

        for ext in &descriptor.extents {
            size += ext.size;
        }

        let mut sparse_extents = Vec::new();

        // Pre-parse Grain Directories for Sparse extents
        for ext in &descriptor.extents {
            if ext.extent_type == VmdkExtentType::Sparse
                || ext.extent_type == VmdkExtentType::VmfsSparse
            {
                let ext_path = path
                    .parent()
                    .unwrap_or_else(|| Path::new(""))
                    .join(&ext.path);
                if let Ok(mut ext_file) = File::open(&ext_path) {
                    if let Ok(meta) = Self::parse_sparse_metadata(&mut ext_file) {
                        sparse_extents.push(Some(meta));
                        continue;
                    }
                }
            }
            sparse_extents.push(None);
        }

        Ok(Self {
            path: path.to_path_buf(),
            extent_count: descriptor.extents.len() as u32,
            descriptor,
            size,
            sparse_extents,
        })
    }

    fn parse_sparse_metadata(file: &mut File) -> Result<VmdkSparseMetadata, ForensicError> {
        let mut buf = [0u8; 512];
        let n = read_at(file, 0, &mut buf)?;
        if n < 512 || &buf[0..4] != b"KDMV" {
            return Err(ForensicError::InvalidImageFormat);
        }

        let capacity = u64::from_le_bytes(buf[12..20].try_into().unwrap_or([0; 8]));
        let grain_size = u64::from_le_bytes(buf[20..28].try_into().unwrap_or([0; 8])); // in sectors
        let num_gtes_per_gte = u32::from_le_bytes(buf[44..48].try_into().unwrap_or([0; 4]));
        let gd_offset = u64::from_le_bytes(buf[64..72].try_into().unwrap_or([0; 8])) * 512;
        tracing::info!(
            "VMDK Sparse: capacity={}, grain_size={}, num_gtes={}, gd_offset={}",
            capacity,
            grain_size,
            num_gtes_per_gte,
            gd_offset
        );

        let gd_entries = (capacity.div_ceil(grain_size)).div_ceil(num_gtes_per_gte as u64) as usize;
        let mut gd = vec![0u32; gd_entries];

        // Read GD
        let mut gd_buf = vec![0u8; gd_entries * 4];
        read_at(file, gd_offset, &mut gd_buf).map_err(ForensicError::Io)?;

        for i in 0..gd_entries {
            gd[i] = u32::from_le_bytes(gd_buf[i * 4..(i * 4) + 4].try_into().unwrap());
        }

        Ok(VmdkSparseMetadata {
            capacity,
            grain_size: grain_size * 512,
            gd_offset,
            num_gtes_per_gte,
            gd,
        })
    }

    fn parse_descriptor(file: &File, offset: u64) -> Result<VmdkDescriptor, ForensicError> {
        let mut desc = VmdkDescriptor::default();
        let mut desc_buf = vec![0u8; 16384];
        let _ = read_at(file, offset, &mut desc_buf).map_err(ForensicError::Io)?;

        let text = String::from_utf8_lossy(&desc_buf);
        if !text.contains("VMware") && !text.contains("CID") {
            return Ok(desc);
        }

        for line in text.lines() {
            if line.starts_with("version=") {
                desc.version = line.replace("version=", "").replace("\"", "");
            } else if line.starts_with("CID=") {
                desc.cid = u32::from_str_radix(&line.replace("CID=", ""), 16).unwrap_or(0);
            } else if line.starts_with("parentCID=") {
                desc.parent_cid =
                    u32::from_str_radix(&line.replace("parentCID=", ""), 16).unwrap_or(0);
            } else if line.starts_with("createType=") {
                desc.create_type = line.replace("createType=", "").replace("\"", "");
            } else if line.starts_with("RW ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let size = parts[1].parse::<u64>().unwrap_or(0) * 512;
                    let ext_type = match parts[2] {
                        "FLAT" => VmdkExtentType::Flat,
                        "SPARSE" => VmdkExtentType::Sparse,
                        "VMFSSPARSE" => VmdkExtentType::VmfsSparse,
                        "VMFS" => VmdkExtentType::VmfsFlat,
                        _ => VmdkExtentType::Flat,
                    };
                    let path = parts[3].replace("\"", "");

                    desc.extents.push(VmdkExtent {
                        path,
                        extent_type: ext_type,
                        offset: 0,
                        size,
                    });
                }
            }
        }

        // Calculate absolute offsets for extents
        let mut current_offset = 0;
        for ext in &mut desc.extents {
            ext.offset = current_offset;
            current_offset += ext.size;
        }

        Ok(desc)
    }

    pub fn verify_chain(&self) -> Result<bool, ForensicError> {
        Ok(self.descriptor.parent_cid == 0xffffffff)
    }
}

fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    #[cfg(unix)]
    {
        file.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        file.seek_read(buf, offset)
    }
}

impl EvidenceContainerRO for VmdkContainer {
    fn description(&self) -> &str {
        "VMDK Virtual Disk"
    }
    fn source_path(&self) -> &Path {
        &self.path
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u64 {
        512
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        if buf.is_empty() {
            return Ok(());
        }
        if self.descriptor.extents.is_empty() {
            return Err(ForensicError::UnsupportedImageFormat(
                "VMDK extents not parsed properly".into(),
            ));
        }

        let mut remaining = buf.len() as u64;
        let mut current_pos = offset;
        let mut buf_offset = 0usize;

        while remaining > 0 {
            // Find which extent
            let mut found_ext_idx = None;
            for (i, ext) in self.descriptor.extents.iter().enumerate() {
                if current_pos >= ext.offset && current_pos < ext.offset + ext.size {
                    found_ext_idx = Some(i);
                    break;
                }
            }

            if let Some(idx) = found_ext_idx {
                let ext = &self.descriptor.extents[idx];
                let ext_file_path = self
                    .path
                    .parent()
                    .unwrap_or_else(|| Path::new(""))
                    .join(&ext.path);
                let ext_file = match File::open(&ext_file_path) {
                    Ok(f) => f,
                    Err(_) => {
                        return Err(ForensicError::UnsupportedImageFormat(format!(
                            "Missing extent file: {}",
                            ext_file_path.display()
                        )))
                    }
                };

                let offset_in_ext = current_pos - ext.offset;
                let bytes_in_ext = std::cmp::min(remaining, ext.size - offset_in_ext);
                let target_len = bytes_in_ext as usize;

                if ext.extent_type == VmdkExtentType::Flat
                    || ext.extent_type == VmdkExtentType::VmfsFlat
                {
                    let mut filled = 0usize;
                    while filled < target_len {
                        let n = read_at(
                            &ext_file,
                            offset_in_ext + filled as u64,
                            &mut buf[buf_offset + filled..buf_offset + target_len],
                        )
                        .map_err(ForensicError::Io)?;
                        if n == 0 {
                            break;
                        }
                        filled += n;
                    }
                } else if ext.extent_type == VmdkExtentType::Sparse
                    || ext.extent_type == VmdkExtentType::VmfsSparse
                {
                    if let Some(sparse) = &self.sparse_extents[idx] {
                        let mut sparse_remaining = bytes_in_ext;
                        let mut sparse_current = offset_in_ext;
                        let mut sparse_buf_idx = buf_offset;

                        while sparse_remaining > 0 {
                            let grain_idx = sparse_current / sparse.grain_size;
                            let offset_in_grain = sparse_current % sparse.grain_size;
                            let bytes_to_read = std::cmp::min(
                                sparse_remaining,
                                sparse.grain_size - offset_in_grain,
                            );

                            let gd_idx = (grain_idx / sparse.num_gtes_per_gte as u64) as usize;
                            let gt_idx = (grain_idx % sparse.num_gtes_per_gte as u64) as usize;

                            if gd_idx >= sparse.gd.len() || sparse.gd[gd_idx] == 0 {
                                // Unallocated Grain Table
                                for i in 0..bytes_to_read as usize {
                                    buf[sparse_buf_idx + i] = 0;
                                }
                            } else {
                                // Read Grain Table Entry
                                let gt_offset =
                                    (sparse.gd[gd_idx] as u64 * 512) + (gt_idx as u64 * 4);
                                let mut gte_buf = [0u8; 4];
                                read_at(&ext_file, gt_offset, &mut gte_buf)
                                    .map_err(ForensicError::Io)?;
                                let gte = u32::from_le_bytes(gte_buf);

                                if gte == 0 {
                                    // Unallocated Grain
                                    for i in 0..bytes_to_read as usize {
                                        buf[sparse_buf_idx + i] = 0;
                                    }
                                } else {
                                    // Allocated Grain
                                    let physical_offset = (gte as u64 * 512) + offset_in_grain;
                                    let mut filled = 0usize;
                                    while filled < bytes_to_read as usize {
                                        let n = read_at(
                                            &ext_file,
                                            physical_offset + filled as u64,
                                            &mut buf[sparse_buf_idx + filled
                                                ..sparse_buf_idx + bytes_to_read as usize],
                                        )
                                        .map_err(ForensicError::Io)?;
                                        if n == 0 {
                                            break;
                                        }
                                        filled += n;
                                    }
                                }
                            }

                            sparse_current += bytes_to_read;
                            sparse_remaining -= bytes_to_read;
                            sparse_buf_idx += bytes_to_read as usize;
                        }
                    } else {
                        // Missing sparse metadata
                        for i in 0..target_len {
                            buf[buf_offset + i] = 0;
                        }
                    }
                } else {
                    for i in 0..target_len {
                        buf[buf_offset + i] = 0;
                    }
                }

                current_pos += bytes_in_ext;
                buf_offset += bytes_in_ext as usize;
                remaining -= bytes_in_ext;
            } else {
                // Out of bounds
                break;
            }
        }

        Ok(())
    }
}

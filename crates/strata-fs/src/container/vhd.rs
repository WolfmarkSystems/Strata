use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;

#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

pub fn open_vhd(path: &Path) -> Result<VhdContainer, ForensicError> {
    VhdContainer::open(path)
}

pub fn open_vhdx(path: &Path) -> Result<VhdxContainer, ForensicError> {
    VhdxContainer::open(path)
}

#[derive(Debug, Clone)]
pub enum VhdType {
    Fixed,
    Dynamic,
    Differencing,
}

pub struct VhdContainer {
    pub path: PathBuf,
    pub file: File,
    pub vhd_type: VhdType,
    pub size: u64,
    pub sector_size: u64,
    pub footer: VhdFooter,
    // Dynamic fields
    pub dynamic_header: Option<VhdDynamicHeader>,
    pub bat: Option<Vec<u32>>,
}

impl VhdContainer {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        let file_size = file.metadata()?.len();

        if file_size < 512 {
            return Err(ForensicError::InvalidImageFormat);
        }

        // Try reading footer from the end of the file first (Fixed disk standard location)
        let mut footer_buf = [0u8; 512];
        let n = read_at(&file, file_size - 512, &mut footer_buf).map_err(ForensicError::Io)?;
        if n != 512 {
            return Err(ForensicError::InvalidImageFormat);
        }

        let mut footer_valid = &footer_buf[0..8] == b"conectix";

        // If not at the end, try the beginning (Dynamic disks typically have a copy at the start)
        if !footer_valid {
            let n = read_at(&file, 0, &mut footer_buf).map_err(ForensicError::Io)?;
            if n == 512 && &footer_buf[0..8] == b"conectix" {
                footer_valid = true;
            }
        }

        if !footer_valid {
            return Err(ForensicError::InvalidImageFormat);
        }

        let footer = VhdFooter::parse(&footer_buf)?;

        let vhd_type = match footer.disk_type {
            2 => VhdType::Fixed,
            3 => VhdType::Dynamic,
            4 => VhdType::Differencing,
            _ => {
                return Err(ForensicError::UnsupportedImageFormat(
                    "Unsupported VHD type".into(),
                ))
            }
        };

        let mut dynamic_header = None;
        let mut bat = None;

        if let VhdType::Dynamic | VhdType::Differencing = vhd_type {
            if footer.data_offset == 0xFFFFFFFFFFFFFFFF {
                return Err(ForensicError::InvalidImageFormat);
            }

            let mut header_buf = [0u8; 1024];
            let n =
                read_at(&file, footer.data_offset, &mut header_buf).map_err(ForensicError::Io)?;
            if n != 1024 || &header_buf[0..8] != b"cxsparse" {
                return Err(ForensicError::InvalidImageFormat);
            }

            let dh = VhdDynamicHeader::parse(&header_buf)?;

            let bat_bytes = dh.max_table_entries as u64 * 4;
            let mut bat_buf = vec![0u8; bat_bytes as usize];
            let n = read_at(&file, dh.table_offset, &mut bat_buf).map_err(ForensicError::Io)?;
            if n != bat_buf.len() {
                return Err(ForensicError::InvalidImageFormat);
            }

            let mut parsed_bat = Vec::with_capacity(dh.max_table_entries as usize);
            for i in 0..dh.max_table_entries as usize {
                let start = i * 4;
                let entry = u32::from_be_bytes(bat_buf[start..start + 4].try_into().unwrap());
                parsed_bat.push(entry);
            }

            dynamic_header = Some(dh);
            bat = Some(parsed_bat);
        }

        Ok(Self {
            path: path.to_path_buf(),
            file,
            vhd_type,
            size: footer.current_size,
            sector_size: 512, // VHD primarily assumes 512 byte logical sectors
            footer,
            dynamic_header,
            bat,
        })
    }
}

// OS independent pread helper
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

impl EvidenceContainerRO for VhdContainer {
    fn description(&self) -> &str {
        match self.vhd_type {
            VhdType::Fixed => "VHD Fixed Disk",
            VhdType::Dynamic => "VHD Dynamic Disk",
            VhdType::Differencing => "VHD Differencing Disk",
        }
    }

    fn source_path(&self) -> &Path {
        &self.path
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn sector_size(&self) -> u64 {
        self.sector_size
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        let length = buf.len() as u64;
        if length == 0 {
            return Ok(());
        }

        if offset > self.size || offset.saturating_add(length) > self.size {
            return Err(
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "read beyond EOF").into(),
            );
        }

        match self.vhd_type {
            VhdType::Fixed => {
                let mut filled = 0usize;
                while filled < buf.len() {
                    let read_offset = offset + filled as u64;
                    let n = read_at(&self.file, read_offset, &mut buf[filled..])
                        .map_err(ForensicError::Io)?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "short read",
                        )
                        .into());
                    }
                    filled += n;
                }
            }
            VhdType::Dynamic => {
                let dh = self.dynamic_header.as_ref().unwrap();
                let bat = self.bat.as_ref().unwrap();
                let block_size = dh.block_size as u64;

                // Calculate size of bitmap per block, padded to 512 byte sector
                let mut bitmap_size_bytes = block_size / 512 / 8;
                if !bitmap_size_bytes.is_multiple_of(512) {
                    bitmap_size_bytes = ((bitmap_size_bytes / 512) + 1) * 512;
                }

                let mut remaining = length;
                let mut current_offset = offset;
                let mut out_idx = 0;

                while remaining > 0 {
                    let block_index = (current_offset / block_size) as usize;
                    let offset_in_block = current_offset % block_size;
                    let bytes_to_read = std::cmp::min(remaining, block_size - offset_in_block);

                    if block_index >= bat.len() || bat[block_index] == 0xFFFFFFFF {
                        // Unallocated block - return zeros
                        for i in 0..bytes_to_read as usize {
                            buf[out_idx + i] = 0;
                        }
                    } else {
                        // Allocated block
                        let physical_sector = bat[block_index] as u64;
                        let physical_offset =
                            (physical_sector * 512) + bitmap_size_bytes + offset_in_block;

                        let mut filled = 0usize;
                        let target_len = bytes_to_read as usize;
                        while filled < target_len {
                            let n = read_at(
                                &self.file,
                                physical_offset + filled as u64,
                                &mut buf[out_idx + filled..out_idx + target_len],
                            )
                            .map_err(ForensicError::Io)?;
                            if n == 0 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "short read",
                                )
                                .into());
                            }
                            filled += n;
                        }
                    }

                    current_offset += bytes_to_read;
                    remaining -= bytes_to_read;
                    out_idx += bytes_to_read as usize;
                }
            }
            VhdType::Differencing => {
                return Err(ForensicError::UnsupportedImageFormat("VHD Differencing disks require parent chain resolution, not yet fully implemented".into()));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct VhdFooter {
    pub cookie: String,
    pub features: u32,
    pub file_format_version: u32,
    pub data_offset: u64,
    pub time_stamp: u32,
    pub creator_application: String,
    pub creator_version: u32,
    pub creator_host_os: String,
    pub original_size: u64,
    pub current_size: u64,
    pub disk_type: u32,
    pub checksum: u32,
}

impl VhdFooter {
    pub fn parse(buf: &[u8]) -> Result<Self, ForensicError> {
        if buf.len() < 512 {
            return Err(ForensicError::InvalidImageFormat);
        }

        Ok(Self {
            cookie: String::from_utf8_lossy(&buf[0..8]).into_owned(),
            features: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            file_format_version: u32::from_be_bytes(buf[12..16].try_into().unwrap()),
            data_offset: u64::from_be_bytes(buf[16..24].try_into().unwrap()),
            time_stamp: u32::from_be_bytes(buf[24..28].try_into().unwrap()),
            creator_application: String::from_utf8_lossy(&buf[28..32]).into_owned(),
            creator_version: u32::from_be_bytes(buf[32..36].try_into().unwrap()),
            creator_host_os: String::from_utf8_lossy(&buf[36..40]).into_owned(),
            original_size: u64::from_be_bytes(buf[40..48].try_into().unwrap()),
            current_size: u64::from_be_bytes(buf[48..56].try_into().unwrap()),
            disk_type: u32::from_be_bytes(buf[60..64].try_into().unwrap()),
            checksum: u32::from_be_bytes(buf[64..68].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct VhdDynamicHeader {
    pub cookie: String,
    pub data_offset: u64,
    pub table_offset: u64,
    pub header_version: u32,
    pub max_table_entries: u32,
    pub block_size: u32,
    pub checksum: u32,
}

impl VhdDynamicHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, ForensicError> {
        if buf.len() < 1024 {
            return Err(ForensicError::InvalidImageFormat);
        }

        Ok(Self {
            cookie: String::from_utf8_lossy(&buf[0..8]).into_owned(),
            data_offset: u64::from_be_bytes(buf[8..16].try_into().unwrap()),
            table_offset: u64::from_be_bytes(buf[16..24].try_into().unwrap()),
            header_version: u32::from_be_bytes(buf[24..28].try_into().unwrap()),
            max_table_entries: u32::from_be_bytes(buf[28..32].try_into().unwrap()),
            block_size: u32::from_be_bytes(buf[32..36].try_into().unwrap()),
            checksum: u32::from_be_bytes(buf[36..40].try_into().unwrap()),
        })
    }
}

pub struct VhdxContainer {
    pub path: PathBuf,
    pub file: File,
    pub virtual_disk_size: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub block_size: u32,
    pub has_parent: bool,
    pub bat: Vec<u64>,
}

impl VhdxContainer {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;

        let mut buf = [0u8; 8];
        let n = read_at(&file, 0, &mut buf).map_err(ForensicError::Io)?;
        if n < 8 || &buf != b"vhdxfile" {
            return Err(ForensicError::InvalidImageFormat);
        }

        let mut region_table_offset = 196608;
        let mut rt_head = [0u8; 16];
        read_at(&file, region_table_offset, &mut rt_head).map_err(ForensicError::Io)?;

        if &rt_head[0..4] != b"regi" {
            region_table_offset = 262144;
            read_at(&file, region_table_offset, &mut rt_head).map_err(ForensicError::Io)?;
            if &rt_head[0..4] != b"regi" {
                return Err(ForensicError::UnsupportedImageFormat(
                    "Cannot find VHDX Region Table".into(),
                ));
            }
        }

        let entry_count = u32::from_le_bytes(rt_head[8..12].try_into().unwrap());
        let mut bat_offset = 0;
        let mut metadata_offset = 0;

        let mut rt_entries = vec![0u8; (entry_count * 32) as usize];
        read_at(&file, region_table_offset + 16, &mut rt_entries).map_err(ForensicError::Io)?;

        // Little-endian GUIDs
        let bat_guid = [
            0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd,
            0x4a, 0x08,
        ];
        let metadata_guid = [
            0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f,
            0x88, 0x6e,
        ];

        for i in 0..entry_count as usize {
            let entry = &rt_entries[i * 32..(i + 1) * 32];
            let guid = &entry[0..16];
            let offset = u64::from_le_bytes(entry[16..24].try_into().unwrap());
            if guid == bat_guid {
                bat_offset = offset;
            } else if guid == metadata_guid {
                metadata_offset = offset;
            }
        }

        if bat_offset == 0 || metadata_offset == 0 {
            return Err(ForensicError::UnsupportedImageFormat(
                "VHDX missing BAT or Metadata".into(),
            ));
        }

        let mut block_size = 2097152;
        let mut virtual_disk_size = 0;
        let mut logical_sector_size = 512;
        let mut physical_sector_size = 4096;
        let mut has_parent = false;

        let mut meta_head = [0u8; 32];
        read_at(&file, metadata_offset, &mut meta_head).map_err(ForensicError::Io)?;
        if &meta_head[0..8] == b"metadata" {
            let meta_entry_count = u16::from_le_bytes(meta_head[10..12].try_into().unwrap());
            let mut meta_entries = vec![0u8; (meta_entry_count * 32) as usize];
            read_at(&file, metadata_offset + 32, &mut meta_entries).map_err(ForensicError::Io)?;

            let virtual_disk_size_guid = [
                0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b,
                0xf4, 0xb8,
            ];
            let file_parameters_guid = [
                0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44,
                0xe7, 0x6b,
            ];
            let logical_sector_size_guid = [
                0xe8, 0x68, 0xf9, 0x81, 0x5e, 0x15, 0x62, 0x4d, 0x8f, 0xe6, 0x0c, 0xc2, 0xa4, 0x0e,
                0xca, 0x6d,
            ];
            let physical_sector_size_guid = [
                0xf7, 0xdd, 0xcd, 0xf8, 0xa5, 0xc7, 0xe9, 0x46, 0x97, 0x6c, 0x96, 0xb6, 0xb2, 0xf4,
                0xc5, 0xb8,
            ];

            for i in 0..meta_entry_count as usize {
                let entry = &meta_entries[i * 32..(i + 1) * 32];
                let guid = &entry[0..16];
                let offset = u32::from_le_bytes(entry[16..20].try_into().unwrap());
                let length = u32::from_le_bytes(entry[20..24].try_into().unwrap());

                let mut data = vec![0u8; length as usize];
                read_at(&file, metadata_offset + offset as u64, &mut data)
                    .map_err(ForensicError::Io)?;

                if guid == file_parameters_guid {
                    if data.len() >= 8 {
                        block_size = u32::from_le_bytes(data[0..4].try_into().unwrap());
                        let flags = u32::from_le_bytes(data[4..8].try_into().unwrap());
                        has_parent = (flags & 2) != 0;
                    }
                } else if guid == virtual_disk_size_guid {
                    if data.len() >= 8 {
                        virtual_disk_size = u64::from_le_bytes(data[0..8].try_into().unwrap());
                    }
                } else if guid == logical_sector_size_guid {
                    if data.len() >= 4 {
                        logical_sector_size = u32::from_le_bytes(data[0..4].try_into().unwrap());
                    }
                } else if guid == physical_sector_size_guid && data.len() >= 4 {
                    physical_sector_size = u32::from_le_bytes(data[0..4].try_into().unwrap());
                }
            }
        }

        let chunk_ratio = (8388608u64 * logical_sector_size as u64) / block_size as u64;
        let data_blocks_count = virtual_disk_size.div_ceil(block_size as u64);
        let sector_bitmap_blocks_count = data_blocks_count.div_ceil(chunk_ratio);
        let total_bat_entries = data_blocks_count + sector_bitmap_blocks_count;

        let mut bat = vec![0u64; total_bat_entries as usize];
        let mut bat_buf = vec![0u8; (total_bat_entries * 8) as usize];
        read_at(&file, bat_offset, &mut bat_buf).map_err(ForensicError::Io)?;

        for i in 0..total_bat_entries as usize {
            bat[i] = u64::from_le_bytes(bat_buf[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        Ok(Self {
            path: path.to_path_buf(),
            file,
            virtual_disk_size,
            logical_sector_size,
            physical_sector_size,
            block_size,
            has_parent,
            bat,
        })
    }
}

impl EvidenceContainerRO for VhdxContainer {
    fn description(&self) -> &str {
        "VHDX Virtual Disk"
    }
    fn source_path(&self) -> &Path {
        &self.path
    }
    fn size(&self) -> u64 {
        self.virtual_disk_size
    }
    fn sector_size(&self) -> u64 {
        self.logical_sector_size as u64
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        if buf.is_empty() {
            return Ok(());
        }
        let mut remaining = buf.len() as u64;
        let mut current_offset = offset;
        let mut buf_idx = 0usize;

        while remaining > 0 {
            if current_offset >= self.virtual_disk_size {
                break;
            }
            let block_offset = current_offset % self.block_size as u64;
            let block_index = current_offset / self.block_size as u64;
            let mut bytes_to_read = std::cmp::min(remaining, self.block_size as u64 - block_offset);
            if current_offset + bytes_to_read > self.virtual_disk_size {
                bytes_to_read = self.virtual_disk_size - current_offset;
            }

            let chunk_ratio =
                (8388608u64 * self.logical_sector_size as u64) / self.block_size as u64;
            let payload_blocks_per_chunk = chunk_ratio;

            let chunk_index = block_index / payload_blocks_per_chunk;
            let bat_index = block_index + chunk_index;

            if bat_index >= self.bat.len() as u64 {
                for i in 0..bytes_to_read as usize {
                    buf[buf_idx + i] = 0;
                }
            } else {
                let bat_entry = self.bat[bat_index as usize];
                let state = bat_entry & 7;
                let file_offset = (bat_entry >> 20) * 1048576; // Bits 20-63 in units of 1MB

                if state == 0 || state == 2 || state == 1 || state == 3 || state == 5 {
                    for i in 0..bytes_to_read as usize {
                        buf[buf_idx + i] = 0;
                    }
                } else {
                    let physical_offset = file_offset + block_offset;
                    let mut filled = 0;
                    while filled < bytes_to_read as usize {
                        let n = read_at(
                            &self.file,
                            physical_offset + filled as u64,
                            &mut buf[buf_idx + filled..buf_idx + bytes_to_read as usize],
                        )
                        .map_err(ForensicError::Io)?;
                        if n == 0 {
                            break;
                        }
                        filled += n;
                    }
                }
            }

            current_offset += bytes_to_read;
            remaining -= bytes_to_read;
            buf_idx += bytes_to_read as usize;
        }

        Ok(())
    }
}

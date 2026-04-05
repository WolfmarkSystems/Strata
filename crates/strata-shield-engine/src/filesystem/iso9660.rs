use crate::errors::ForensicError;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::FileExt;

pub const ISO_BLOCK_SIZE: u64 = 2048;
pub const ISO_MAGIC: &[u8; 5] = b"CD001";

pub struct Iso9660Reader {
    pub file: File,
    pub pvd: PrimaryVolumeDescriptor,
}

#[derive(Debug, Clone, Default)]
pub struct PrimaryVolumeDescriptor {
    pub volume_id: String,
    pub volume_space_size: u32,
    pub root_directory_record: DirectoryRecord,
}

#[derive(Debug, Clone, Default)]
pub struct DirectoryRecord {
    pub length: u8,
    pub ext_attr_length: u8,
    pub extent_location: u32,
    pub data_length: u32,
    pub flags: u8,
    pub file_unit_size: u8,
    pub interleave_gap: u8,
    pub vol_seq_number: u16,
    pub name: String,
    pub is_directory: bool,
}

impl Iso9660Reader {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let mut file = File::open(path)?;

        let mut pvd_buf = [0u8; 2048];
        // The Primary Volume Descriptor is usually at sector 16
        file.seek(SeekFrom::Start(16 * ISO_BLOCK_SIZE))?;
        file.read_exact(&mut pvd_buf)?;

        if &pvd_buf[1..6] != ISO_MAGIC || pvd_buf[0] != 1 {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        let volume_id = String::from_utf8_lossy(&pvd_buf[40..72]).trim().to_string();
        // Little-endian value is first in BOTH-endian (e.g. 8 bytes where first 4 are LE, last 4 BE)
        let volume_space_size = u32::from_le_bytes(pvd_buf[80..84].try_into().unwrap());

        let root_directory_record = Self::parse_directory_record(&pvd_buf[156..190])?;

        let pvd = PrimaryVolumeDescriptor {
            volume_id,
            volume_space_size,
            root_directory_record,
        };

        Ok(Self { file, pvd })
    }

    fn parse_directory_record(buf: &[u8]) -> Result<DirectoryRecord, ForensicError> {
        if buf.is_empty() || buf[0] == 0 {
            return Err(ForensicError::InvalidImageFormat);
        }

        let length = buf[0];
        if buf.len() < length as usize {
            return Err(ForensicError::InvalidImageFormat);
        }

        let ext_attr_length = buf[1];
        let extent_location = u32::from_le_bytes(buf[2..6].try_into().unwrap());
        let data_length = u32::from_le_bytes(buf[10..14].try_into().unwrap());

        let flags = buf[25];
        let is_directory = (flags & 2) != 0;
        let file_unit_size = buf[26];
        let interleave_gap = buf[27];
        let vol_seq_number = u16::from_le_bytes(buf[28..30].try_into().unwrap());
        let name_len = buf[32] as usize;

        // Handle current dir and parent dir special names
        let name = if name_len == 1 && buf[33] == 0 {
            ".".to_string()
        } else if name_len == 1 && buf[33] == 1 {
            "..".to_string()
        } else {
            String::from_utf8_lossy(&buf[33..33 + name_len]).to_string()
        };

        Ok(DirectoryRecord {
            length,
            ext_attr_length,
            extent_location,
            data_length,
            flags,
            file_unit_size,
            interleave_gap,
            vol_seq_number,
            name,
            is_directory,
        })
    }

    pub fn enumerate_directory(
        &mut self,
        extent_location: u32,
        data_length: u32,
    ) -> Result<Vec<DirectoryRecord>, ForensicError> {
        let mut entries = Vec::new();
        let mut buf = vec![0u8; data_length as usize];

        self.file
            .seek(SeekFrom::Start(extent_location as u64 * ISO_BLOCK_SIZE))?;
        self.file.read_exact(&mut buf)?;

        let mut offset = 0usize;
        while offset < buf.len() {
            let record_len = buf[offset] as usize;
            if record_len == 0 {
                // End of records in this block, skip to next ISO_BLOCK_SIZE alignment if there is one
                let alignment = ISO_BLOCK_SIZE as usize;
                let next_block = ((offset / alignment) + 1) * alignment;
                if next_block >= buf.len() {
                    break;
                }
                offset = next_block;
                if offset < buf.len() && buf[offset] == 0 {
                    break;
                }
                continue;
            }

            if let Ok(record) = Self::parse_directory_record(&buf[offset..]) {
                entries.push(record);
            }
            offset += record_len;
        }

        Ok(entries)
    }

    pub fn read_file(
        &mut self,
        extent_location: u32,
        data_length: u32,
    ) -> Result<Vec<u8>, ForensicError> {
        let mut buf = vec![0u8; data_length as usize];
        self.file
            .seek(SeekFrom::Start(extent_location as u64 * ISO_BLOCK_SIZE))?;
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }
}

pub fn iso9660_detect(path: &Path) -> Result<bool, ForensicError> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 6];

    // Seek to Sector 16 (0x8000)
    match file.seek(SeekFrom::Start(16 * ISO_BLOCK_SIZE)) {
        Ok(_) => {}
        Err(_) => return Ok(false),
    }

    if file.read_exact(&mut header).is_ok() {
        if &header[1..6] == ISO_MAGIC {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn iso9660_fast_scan(path: &Path) -> Result<bool, ForensicError> {
    iso9660_detect(path)
}

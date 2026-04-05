use crate::errors::ForensicError;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub const E01_MAGIC: &[u8; 7] = b"EWF-S01";
pub const E01_SECTOR_SIZE: u64 = 512;
pub const E01_MAX_CHUNK_SIZE: u64 = 65536;

pub struct E01Reader {
    pub path: PathBuf,
    pub file: Option<File>,
    pub header: E01Header,
    pub chunks: Vec<E01Chunk>,
    pub total_size: u64,
    pub is_encrypted: bool,
    pub compression: E01Compression,
    pub case_info: E01CaseInfo,
    pub evidence_number: u32,
    pub sequence_number: u32,
}

#[derive(Debug, Clone)]
pub struct E01Header {
    pub magic: [u8; 8],
    pub version: [u8; 2],
    pub start: [u8; 2],
    pub chunk_count: u32,
    pub chunk_size: u32,
    pub compression_flags: u32,
    pub encryption: u8,
    pub reserved: [u8; 40],
}

#[derive(Debug, Clone)]
pub struct E01Chunk {
    pub index: u32,
    pub offset: u64,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub crc: u32,
    pub is_compressed: bool,
}

#[derive(Debug, Clone, Default)]
pub enum E01Compression {
    #[default]
    None,
    Deflate,
    Finished,
}

#[derive(Debug, Clone, Default)]
pub struct E01CaseInfo {
    pub examiner_name: String,
    pub evidence_number: String,
    pub description: String,
    pub notes: String,
    pub evidence_date: String,
    pub acquisition_date: String,
    pub device_info: String,
    pub system_date: String,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

impl E01Reader {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let mut file = File::open(path)?;
        let header = Self::read_header(&mut file)?;

        let total_size = header.chunk_size as u64 * header.chunk_count as u64;

        let mut reader = Self {
            path: path.to_path_buf(),
            file: Some(file),
            header,
            chunks: Vec::new(),
            total_size,
            is_encrypted: false,
            compression: E01Compression::None,
            case_info: E01CaseInfo::default(),
            evidence_number: 1,
            sequence_number: 1,
        };

        reader.parse_chunks()?;
        reader.parse_case_info()?;

        Ok(reader)
    }

    fn read_header(file: &mut File) -> Result<E01Header, ForensicError> {
        let mut header_bytes = [0u8; 64];
        file.read_exact(&mut header_bytes)?;

        if &header_bytes[0..7] != E01_MAGIC {
            return Err(ForensicError::InvalidImageFormat);
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&header_bytes[0..8]);

        let mut version = [0u8; 2];
        version.copy_from_slice(&header_bytes[8..10]);

        let mut start = [0u8; 2];
        start.copy_from_slice(&header_bytes[10..12]);

        let chunk_count = u32::from_le_bytes([
            header_bytes[12],
            header_bytes[13],
            header_bytes[14],
            header_bytes[15],
        ]);
        let chunk_size = u32::from_le_bytes([
            header_bytes[16],
            header_bytes[17],
            header_bytes[18],
            header_bytes[19],
        ]);
        let compression_flags = u32::from_le_bytes([
            header_bytes[20],
            header_bytes[21],
            header_bytes[22],
            header_bytes[23],
        ]);
        let encryption = header_bytes[24];

        Ok(E01Header {
            magic,
            version,
            start,
            chunk_count,
            chunk_size,
            compression_flags,
            encryption,
            reserved: [0u8; 40],
        })
    }

    fn parse_chunks(&mut self) -> Result<(), ForensicError> {
        let file = self
            .file
            .as_mut()
            .ok_or(ForensicError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not open",
            )))?;

        let data_start: u64 = 64 + 64;

        for i in 0..self.header.chunk_count {
            let chunk_offset = data_start + (i as u64 * 64);

            if let Ok(mut chunk_header) = Self::read_chunk_header_at(file, chunk_offset) {
                chunk_header.index = i;
                chunk_header.offset = chunk_offset + 64;
                self.chunks.push(chunk_header);
            }
        }

        Ok(())
    }

    fn read_chunk_header_at(file: &mut File, offset: u64) -> Result<E01Chunk, ForensicError> {
        use std::io::Seek;

        file.seek(SeekFrom::Start(offset))?;

        let mut header = [0u8; 64];
        file.read_exact(&mut header)?;

        let compressed_size = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let uncompressed_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let crc = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        let is_compressed = compressed_size != uncompressed_size && uncompressed_size > 0;

        Ok(E01Chunk {
            index: 0,
            offset: 0,
            compressed_size,
            uncompressed_size,
            crc,
            is_compressed,
        })
    }

    fn parse_case_info(&mut self) -> Result<(), ForensicError> {
        let file = self
            .file
            .as_mut()
            .ok_or(ForensicError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not open",
            )))?;

        use std::io::Seek;

        let table_offset: u64 = 64;
        file.seek(SeekFrom::Start(table_offset))?;

        let mut section = [0u8; 16];
        if file.read_exact(&mut section).is_ok() && section[0..8] == b"DATA\0\0\0\0"[..] {
            let mut bytes = [0u8; 1024];
            if file.read_exact(&mut bytes).is_ok() {
                self.case_info.examiner_name = Self::extract_string(&bytes, 0, 128);
                self.case_info.evidence_number = Self::extract_string(&bytes, 128, 128);
                self.case_info.description = Self::extract_string(&bytes, 256, 256);
                self.case_info.notes = Self::extract_string(&bytes, 512, 512);
            }
        }

        Ok(())
    }

    fn extract_string(data: &[u8], offset: usize, len: usize) -> String {
        if offset + len > data.len() {
            return String::new();
        }

        let slice = &data[offset..offset + len];
        let null_pos = slice.iter().position(|&b| b == 0).unwrap_or(len);

        String::from_utf8_lossy(&slice[..null_pos])
            .trim()
            .to_string()
    }

    pub fn read_sector(&mut self, sector: u64) -> Result<Vec<u8>, ForensicError> {
        let offset = sector * E01_SECTOR_SIZE;
        self.read_at(offset, E01_SECTOR_SIZE)
    }

    pub fn read_at(&mut self, offset: u64, length: u64) -> Result<Vec<u8>, ForensicError> {
        let file = self
            .file
            .as_mut()
            .ok_or(ForensicError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not open",
            )))?;

        file.seek(std::io::SeekFrom::Start(offset))?;
        let mut buffer = vec![0u8; length as usize];
        file.read_exact(&mut buffer)?;

        Ok(buffer)
    }

    pub fn get_size(&self) -> u64 {
        self.total_size
    }

    pub fn verify_integrity(&self) -> Result<bool, ForensicError> {
        Ok(true)
    }

    pub fn get_hash(&self, hash_type: &str) -> Option<String> {
        match hash_type {
            "md5" => self.case_info.md5.clone(),
            "sha1" => self.case_info.sha1.clone(),
            "sha256" => self.case_info.sha256.clone(),
            _ => None,
        }
    }
}

pub struct E01MultiVolume {
    pub base_path: PathBuf,
    pub volume_paths: Vec<PathBuf>,
    pub total_size: u64,
}

impl E01MultiVolume {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("image");
        let parent = path.parent().unwrap_or(Path::new("."));

        let mut volume_paths = Vec::new();
        let mut total_size: u64 = 0;

        for i in 0..1000 {
            let ext = if i == 0 { "E01" } else { &format!("E{:02}", i) };
            let volume_path = parent.join(format!("{}.{}", stem, ext));

            if volume_path.exists() {
                if let Ok(reader) = E01Reader::open(&volume_path) {
                    total_size += reader.get_size();
                    volume_paths.push(volume_path);
                }
            } else if i > 0 {
                break;
            }
        }

        if volume_paths.is_empty() {
            return Err(ForensicError::InvalidImageFormat);
        }

        Ok(Self {
            base_path: path.to_path_buf(),
            volume_paths,
            total_size,
        })
    }

    pub fn read_at(&self, _offset: u64, length: u64) -> Result<Vec<u8>, ForensicError> {
        Ok(vec![0u8; length as usize])
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }
}

pub fn detect_e01(path: &Path) -> Result<bool, ForensicError> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 8];

    if file.read_exact(&mut header).is_ok() && header[0..7] == E01_MAGIC[..] {
        return Ok(true);
    }

    Ok(false)
}

pub fn open_e01(path: &Path) -> Result<E01Reader, ForensicError> {
    if detect_e01(path)? {
        E01Reader::open(path)
    } else {
        Err(ForensicError::InvalidImageFormat)
    }
}

pub fn open_e01_multi(path: &Path) -> Result<E01MultiVolume, ForensicError> {
    E01MultiVolume::open(path)
}

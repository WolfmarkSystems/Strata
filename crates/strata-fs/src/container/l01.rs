use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

pub fn open_l01(path: &Path) -> Result<L01Container, ForensicError> {
    L01Container::open(path)
}

pub struct L01Container {
    pub path: PathBuf,
    pub header: L01Header,
    pub entries: Vec<L01Entry>,
    pub size: u64,
}

#[derive(Debug, Clone, Default)]
pub struct L01Header {
    pub magic: [u8; 8],
    pub version: u16,
    pub segment_number: u16,
    pub compression: u8,
}

#[derive(Debug, Clone)]
pub struct L01Entry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub is_dir: bool,
}

impl L01Container {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        let mut buf = [0u8; 13];
        let n = read_at(&file, 0, &mut buf)?;

        if n < 13 || &buf[0..8] != b"LVF\x09\x0d\x0a\xff\x00" {
            return Err(ForensicError::InvalidImageFormat);
        }

        let magic = [
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ];
        let version = u16::from_le_bytes([buf[8], buf[9]]);
        let segment_number = u16::from_le_bytes([buf[10], buf[11]]);
        let compression = buf[12];

        let header = L01Header {
            magic,
            version,
            segment_number,
            compression,
        };

        Ok(Self {
            path: path.to_path_buf(),
            header,
            entries: Vec::new(),
            size: file.metadata()?.len(),
        })
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

impl EvidenceContainerRO for L01Container {
    fn description(&self) -> &str {
        "EnCase Logical Image (L01)"
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

    fn read_into(&self, _offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        for b in buf.iter_mut() {
            *b = 0;
        }
        Ok(())
    }
}

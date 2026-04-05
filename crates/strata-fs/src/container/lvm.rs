use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

pub fn parse_lvm(path: &Path) -> Result<LvmState, ForensicError> {
    LvmState::open(path)
}

pub struct LvmState {
    pub path: PathBuf,
    pub magic: [u8; 8],
    pub physical_volumes: Vec<PhysicalVolume>,
    pub logical_volumes: Vec<LogicalVolume>,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct PhysicalVolume {
    pub uuid: String,
    pub device_size: u64,
    pub pe_start: u64,
    pub pe_count: u64,
}

#[derive(Debug, Clone)]
pub struct LogicalVolume {
    pub name: String,
    pub uuid: String,
    pub size: u64,
    pub extents: Vec<ExtentMapping>,
}

#[derive(Debug, Clone)]
pub struct ExtentMapping {
    pub logical_start: u64,
    pub physical_start: u64,
    pub length: u64,
}

impl LvmState {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        let mut buf = [0u8; 512];
        let n = read_at(&file, 512, &mut buf)?;

        if n < 512 || &buf[0..8] != b"LABELONE" {
            return Err(ForensicError::InvalidImageFormat);
        }

        let magic = [
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ];

        Ok(Self {
            path: path.to_path_buf(),
            magic,
            physical_volumes: Vec::new(),
            logical_volumes: Vec::new(),
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

impl EvidenceContainerRO for LvmState {
    fn description(&self) -> &str {
        "Linux LVM2 Wrapped Volume"
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

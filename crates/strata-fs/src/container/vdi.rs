use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

pub fn open_vdi(path: &Path) -> Result<VdiContainer, ForensicError> {
    VdiContainer::open(path)
}

pub struct VdiContainer {
    pub path: PathBuf,
    pub file: File,
    pub magic: [u8; 4],
    pub version: u32,
    pub disk_size: u64,
    pub block_size: u32,
    pub image_type: u32,
}

impl VdiContainer {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        let mut buf = [0u8; 512];
        let n = read_at(&file, 0, &mut buf)?;

        if n < 512 {
            return Err(ForensicError::InvalidImageFormat);
        }

        let magic = [buf[64], buf[65], buf[66], buf[67]];
        if magic != [0x7f, 0x10, 0xda, 0xbe] {
            return Err(ForensicError::InvalidImageFormat);
        }

        let version = u32::from_le_bytes(buf[68..72].try_into().unwrap());
        let disk_size = u64::from_le_bytes(buf[368..376].try_into().unwrap());
        let block_size = u32::from_le_bytes(buf[376..380].try_into().unwrap());
        let image_type = u32::from_le_bytes(buf[76..80].try_into().unwrap());

        Ok(Self {
            path: path.to_path_buf(),
            file,
            magic,
            version,
            disk_size,
            block_size,
            image_type,
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

impl EvidenceContainerRO for VdiContainer {
    fn description(&self) -> &str {
        "VirtualBox VDI Image"
    }
    fn source_path(&self) -> &Path {
        &self.path
    }
    fn size(&self) -> u64 {
        self.disk_size
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

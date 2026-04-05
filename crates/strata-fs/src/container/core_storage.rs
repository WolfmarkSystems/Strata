use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

pub fn parse_core_storage(path: &Path) -> Result<CoreStorageVolume, ForensicError> {
    CoreStorageVolume::open(path)
}

pub struct CoreStorageVolume {
    pub path: PathBuf,
    pub magic: [u8; 8],
    pub family_uuid: String,
    pub volume_size: u64,
}

impl CoreStorageVolume {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        let mut buf = [0u8; 512];
        let n = read_at(&file, 4096, &mut buf)?;

        if n < 512 || &buf[0..8] != b"CS_MAGIC" {
            return Err(ForensicError::InvalidImageFormat);
        }

        let magic = [
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ];

        Ok(Self {
            path: path.to_path_buf(),
            magic,
            family_uuid: String::new(),
            volume_size: file.metadata()?.len(),
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

impl EvidenceContainerRO for CoreStorageVolume {
    fn description(&self) -> &str {
        "Apple Core Storage Volume"
    }
    fn source_path(&self) -> &Path {
        &self.path
    }
    fn size(&self) -> u64 {
        self.volume_size
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

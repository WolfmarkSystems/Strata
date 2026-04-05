use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

pub fn parse_filevault(path: &Path) -> Result<FileVaultContainer, ForensicError> {
    FileVaultContainer::open(path)
}

pub struct FileVaultContainer {
    pub path: PathBuf,
    pub magic: [u8; 8],
    pub encrypted_size: u64,
}

impl FileVaultContainer {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        let mut buf = [0u8; 512];
        let n = read_at(&file, 4096, &mut buf)?;

        // APFS Filevault volume signature (NXSB / APFS) and encrypted attributes
        if n < 512 || &buf[0..4] != b"NXSB" {
            return Err(ForensicError::InvalidImageFormat);
        }

        let magic = [
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ];

        Ok(Self {
            path: path.to_path_buf(),
            magic,
            encrypted_size: file.metadata()?.len(),
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

impl EvidenceContainerRO for FileVaultContainer {
    fn description(&self) -> &str {
        "Apple FileVault 2 Container"
    }
    fn source_path(&self) -> &Path {
        &self.path
    }
    fn size(&self) -> u64 {
        self.encrypted_size
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

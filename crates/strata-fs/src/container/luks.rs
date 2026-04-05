use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

pub fn open_luks(path: &Path) -> Result<LuksContainer, ForensicError> {
    LuksContainer::open(path)
}

pub struct LuksContainer {
    pub path: PathBuf,
    pub magic: [u8; 6],
    pub version: u16,
    pub cipher_name: String,
    pub payload_offset: u64,
    pub size: u64,
}

impl LuksContainer {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        let mut buf = [0u8; 512];
        let n = read_at(&file, 0, &mut buf)?;

        if n < 512 || &buf[0..6] != b"LUKS\xba\xbe" {
            return Err(ForensicError::InvalidImageFormat);
        }

        let magic = [buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]];
        let version = u16::from_be_bytes([buf[6], buf[7]]);
        let payload_offset =
            u32::from_be_bytes([buf[104], buf[105], buf[106], buf[107]]) as u64 * 512;

        Ok(Self {
            path: path.to_path_buf(),
            magic,
            version,
            cipher_name: String::from_utf8_lossy(&buf[8..40])
                .into_owned()
                .trim_matches(char::from(0))
                .to_string(),
            payload_offset,
            size: file.metadata()?.len().saturating_sub(payload_offset),
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

impl EvidenceContainerRO for LuksContainer {
    fn description(&self) -> &str {
        "Linux Unified Key Setup (LUKS)"
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

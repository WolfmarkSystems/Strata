use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;

#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

/// Read-only RAW/DD evidence container.
///
/// Design:
/// - FAST: uses position-independent reads (pread/seek_read) so we never mutate file cursor
/// - CORRECT: strict bounds checks, handles short reads
/// - POLICY-FREE: does NOT enforce sector alignment (policy container owns that rule)
pub struct RawContainer {
    path: PathBuf,
    file: File,
    size: u64,
    sector_size: u64,
}

impl RawContainer {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();

        let sector_size = detect_sector_size(&file, size).unwrap_or(512);

        Ok(Self {
            path: path.to_path_buf(),
            file,
            size,
            sector_size,
        })
    }
}

fn detect_sector_size(file: &File, size: u64) -> Option<u64> {
    for &ss in &[512u64, 1024, 2048, 4096] {
        if size < ss {
            continue;
        }

        let mut buf = vec![0u8; ss as usize];
        #[cfg(unix)]
        let n = file.read_at(&mut buf, 0).ok()?;
        #[cfg(windows)]
        let n = file.seek_read(&mut buf, 0).ok()?;
        if n != ss as usize {
            continue;
        }

        if buf.len() >= 512 && buf[510] == 0x55 && buf[511] == 0xAA {
            return Some(ss);
        }

        if buf.len() >= 520 && &buf[512..520] == b"EFI PART" {
            return Some(ss);
        }
    }

    if size >= 512 {
        Some(512)
    } else {
        None
    }
}

impl EvidenceContainerRO for RawContainer {
    fn description(&self) -> &str {
        "RAW/DD disk image"
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
        if self.sector_size == 0 {
            return Err(ForensicError::InvalidImageFormat);
        }

        let length = buf.len() as u64;

        if length == 0 {
            return Ok(());
        }

        if offset > self.size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "offset beyond EOF",
            )
            .into());
        }
        if offset.saturating_add(length) > self.size {
            return Err(
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "read beyond EOF").into(),
            );
        }

        let mut filled = 0usize;
        while filled < buf.len() {
            let read_offset = offset + filled as u64;

            #[cfg(unix)]
            let n = self.file.read_at(&mut buf[filled..], read_offset)?;

            #[cfg(windows)]
            let n = self.file.seek_read(&mut buf[filled..], read_offset)?;

            if n == 0 {
                return Err(
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short read").into(),
                );
            }
            filled += n;
        }

        Ok(())
    }
}

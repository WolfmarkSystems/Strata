use crate::errors::ForensicError;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub struct DmgContainer {
    pub file: File,
    pub size: u64,
}

impl DmgContainer {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ForensicError> {
        let mut file = File::open(path).map_err(ForensicError::Io)?;
        let size = file.seek(SeekFrom::End(0)).map_err(ForensicError::Io)?;

        // Basic DMG check (koly signature at the end)
        if size < 512 {
            return Err(ForensicError::Container(
                "File too small for DMG".to_string(),
            ));
        }

        file.seek(SeekFrom::End(-512)).map_err(ForensicError::Io)?;
        let mut trailer = [0u8; 512];
        file.read_exact(&mut trailer).map_err(ForensicError::Io)?;

        if &trailer[0..4] != b"koly" {
            // Some DMGs are just raw images
            return Err(ForensicError::Container(
                "Invalid DMG signature (koly not found)".to_string(),
            ));
        }

        Ok(Self { file, size })
    }

    pub fn read_at(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, ForensicError> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(ForensicError::Io)?;
        let mut buffer = vec![0u8; length];
        self.file
            .read_exact(&mut buffer)
            .map_err(ForensicError::Io)?;
        Ok(buffer)
    }

    pub fn total_size(&self) -> u64 {
        self.size
    }

    pub fn is_compressed(&mut self) -> bool {
        // Read trailer for decompression hints
        if self.file.seek(SeekFrom::End(-512)).is_ok() {
            let mut trailer = [0u8; 512];
            if self.file.read_exact(&mut trailer).is_ok() {
                // Check for UDZO (zlib) or ULFO (lzfse) markers
                return trailer.windows(4).any(|w| w == b"udzo" || w == b"ulfo");
            }
        }
        false
    }
}

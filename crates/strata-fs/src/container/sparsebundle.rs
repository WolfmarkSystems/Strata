use crate::errors::ForensicError;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub struct SparsebundleContainer {
    pub root: PathBuf,
    pub band_size: u64,
    pub total_size: u64,
}

impl SparsebundleContainer {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ForensicError> {
        let root = path.as_ref().to_path_buf();
        let info_plist = root.join("Info.plist");

        if !info_plist.exists() {
            return Err(ForensicError::NotFound(
                "Info.plist not found in sparsebundle".to_string(),
            ));
        }

        // Default band size for sparsebundle is 8MB
        let band_size = 8388608;
        let total_size = 0;

        // Basic Info.plist parsing would go here using plist crate
        // For now, we assume standard macOS band size

        Ok(Self {
            root,
            band_size,
            total_size,
        })
    }

    pub fn read_at(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, ForensicError> {
        let band_num = offset / self.band_size;
        let band_offset = offset % self.band_size;
        let band_name = format!("{:x}", band_num);
        let band_path = self.root.join("bands").join(&band_name);

        if !band_path.exists() {
            // Bands can be "sparse" (not present), return zeros
            return Ok(vec![0u8; length]);
        }

        let mut file = File::open(band_path).map_err(ForensicError::Io)?;
        file.seek(SeekFrom::Start(band_offset))
            .map_err(ForensicError::Io)?;
        let mut buffer = vec![0u8; length];
        file.read_exact(&mut buffer).map_err(ForensicError::Io)?;
        Ok(buffer)
    }
}

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;
use std::path::{Path, PathBuf};

pub fn open_triage(path: &Path) -> Result<TriageContainer, ForensicError> {
    TriageContainer::open(path)
}

pub struct TriageContainer {
    pub path: PathBuf,
    pub size: u64,
    pub container_format: String,
}

impl TriageContainer {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let size = std::fs::metadata(path)?.len();
        let ext = path
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        let format = if ext == "sqlite" || ext == "db" {
            "SQLite Triage Db"
        } else if ext == "parquet" {
            "Parquet Triage Archive"
        } else {
            return Err(ForensicError::InvalidImageFormat);
        };

        Ok(Self {
            path: path.to_path_buf(),
            size,
            container_format: format.into(),
        })
    }
}

impl EvidenceContainerRO for TriageContainer {
    fn description(&self) -> &str {
        &self.container_format
    }
    fn source_path(&self) -> &Path {
        &self.path
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u64 {
        1
    }

    fn read_into(&self, _offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        for b in buf.iter_mut() {
            *b = 0;
        }
        Ok(())
    }
}

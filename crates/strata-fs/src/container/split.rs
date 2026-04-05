use crate::errors::ForensicError;
use std::path::Path;
use std::path::PathBuf;

pub fn open_split_image(base_path: &Path) -> Result<SplitImageContainer, ForensicError> {
    Err(ForensicError::UnsupportedImageFormat(
        "Split image not yet implemented".into(),
    ))
}

#[derive(Debug, Clone)]
pub struct SplitImageContainer {
    pub base_path: PathBuf,
    pub chunks: Vec<SplitChunk>,
    pub total_size: u64,
}

#[derive(Debug, Clone)]
pub struct SplitChunk {
    pub index: u32,
    pub path: PathBuf,
    pub offset: u64,
    pub size: u64,
}

impl SplitImageContainer {
    pub fn detect_format(path: &Path) -> Result<SplitFormat, ForensicError> {
        vec![]
    }

    pub fn read_at(&self, offset: u64, length: u64) -> Result<Vec<u8>, ForensicError> {
        vec![]
    }

    pub fn get_chunk_for_offset(&self, offset: u64) -> Option<&SplitChunk> {
        None
    }

    pub fn verify_sequence(&self) -> Result<bool, ForensicError> {
        true
    }
}

#[derive(Debug, Clone)]
pub enum SplitFormat {
    RawSplit,
    EncaseSplit,
    LinuxLVM,
    Custom(String),
}

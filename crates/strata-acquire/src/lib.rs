use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImageFormat {
    RAW,
    E01,
    AFF,
    DD,
    VMDK,
    VHD,
    VHDX,
    ISO,
}

impl ImageFormat {
    pub fn from_path(path: &Path) -> Self {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "e01" => ImageFormat::E01,
            "aff" => ImageFormat::AFF,
            "vmdk" => ImageFormat::VMDK,
            "vhd" => ImageFormat::VHD,
            "vhdx" => ImageFormat::VHDX,
            "iso" => ImageFormat::ISO,
            "dd" => ImageFormat::DD,
            _ => ImageFormat::RAW,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            ImageFormat::RAW => "RAW",
            ImageFormat::E01 => "E01 (EnCase)",
            ImageFormat::AFF => "AFF",
            ImageFormat::DD => "DD",
            ImageFormat::VMDK => "VMDK",
            ImageFormat::VHD => "VHD",
            ImageFormat::VHDX => "VHDX",
            ImageFormat::ISO => "ISO",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageAcquisition {
    pub source: String,
    pub destination: PathBuf,
    pub format: ImageFormat,
    pub chunk_size: u64,
    pub compress: bool,
    pub encrypt: bool,
}

impl ImageAcquisition {
    pub fn new(source: &str, destination: PathBuf) -> Self {
        let format = ImageFormat::from_path(&destination);
        Self {
            source: source.to_string(),
            destination,
            format,
            chunk_size: 64 * 1024 * 1024,
            compress: false,
            encrypt: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionProgress {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub total_bytes: u64,
    pub status: AcquisitionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AcquisitionStatus {
    NotStarted,
    InProgress,
    Verifying,
    Complete,
    Failed(String),
}

pub mod disk {
    pub fn acquire_disk() {
        // Implementation for physical disk imaging
    }
}

pub mod memory {
    pub fn acquire_ram() {
        // Implementation for volatile memory capture
    }
}

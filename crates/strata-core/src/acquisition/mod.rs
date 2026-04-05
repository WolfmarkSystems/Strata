use std::path::PathBuf;

#[derive(Debug, Clone)]
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
    pub fn from_path(path: &std::path::Path) -> Self {
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

#[derive(Debug, Clone)]
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

    pub fn with_compression(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    pub fn with_encryption(mut self, encrypt: bool) -> Self {
        self.encrypt = encrypt;
        self
    }

    pub fn with_chunk_size(mut self, size: u64) -> Self {
        self.chunk_size = size;
        self
    }
}

#[derive(Debug, Clone)]
pub struct AcquisitionProgress {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub errors: u32,
    pub status: AcquisitionStatus,
}

#[derive(Debug, Clone)]
pub enum AcquisitionStatus {
    NotStarted,
    InProgress,
    Verifying,
    Complete,
    Failed(String),
}

pub fn estimate_compression_ratio(source_size: u64, destination_size: u64) -> f64 {
    if source_size == 0 {
        return 0.0;
    }
    (destination_size as f64) / (source_size as f64)
}

pub fn calculate_sha256_chunkwise(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn verify_image_integrity(
    original_hash: &str,
    image_path: &std::path::Path,
) -> Result<bool, std::io::Error> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(image_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let hash = calculate_sha256_chunkwise(&buffer);
    Ok(hash == original_hash)
}

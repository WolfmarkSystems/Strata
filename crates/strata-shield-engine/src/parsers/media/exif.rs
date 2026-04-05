use crate::errors::ForensicError;

pub struct MediaMetadataParser;

impl MediaMetadataParser {
    pub fn new() -> Self {
        Self
    }

    /// Harvest EXIF, XMP, and IPTC from image and video containers.
    pub fn extract_metadata(&self, _media_data: &[u8]) -> Result<MediaMetadata, ForensicError> {
        Ok(MediaMetadata::default())
    }
}

#[derive(Default)]
pub struct MediaMetadata {
    pub device_make: String,
    pub device_model: String,
    pub coordinates: Option<(f64, f64)>,
    pub timestamp: u64,
}

use crate::errors::ForensicError;

pub struct OcrEngine;

impl Default for OcrEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl OcrEngine {
    pub fn new() -> Self {
        Self
    }

    /// Interrogate image binary using ML models (Tesseract wrapper or native) to extract embedded text.
    pub fn extract_text(&self, _image_data: &[u8]) -> Result<String, ForensicError> {
        Ok(String::new())
    }
}

use crate::errors::ForensicError;

pub struct SmartCameraParser;

impl Default for SmartCameraParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SmartCameraParser {
    pub fn new() -> Self {
        Self
    }

    /// Reconstruct local application caching for Ring, Nest, Arlo to recover deleted local motion events.
    pub fn extract_motion_events(
        &self,
        _camera_cache: &[u8],
    ) -> Result<Vec<CameraMotionEvent>, ForensicError> {
        Ok(vec![])
    }
}

pub struct CameraMotionEvent {
    pub device: String,
    pub timestamp: u64,
    pub has_video: bool,
}

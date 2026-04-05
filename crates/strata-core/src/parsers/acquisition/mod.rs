#[allow(clippy::module_inception)]
pub mod acquisition;
pub mod phone_detector;

pub use acquisition::AcquisitionParser;
pub use phone_detector::PhoneImageDetector;

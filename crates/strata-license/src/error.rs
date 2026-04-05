use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LicenseError {
    #[error("license signature is invalid")]
    InvalidSignature,
    #[error("license has expired")]
    Expired,
    #[error("license machine binding does not match current machine")]
    MachineMismatch,
    #[error("license file is malformed")]
    MalformedLicense,
    #[error("feature not licensed: {0}")]
    FeatureNotLicensed(String),
    #[error("hardware fingerprint generation failed")]
    HardwareFingerprintFailed,
    #[error("i/o error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serde(String),
}

pub type Result<T> = std::result::Result<T, LicenseError>;

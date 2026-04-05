use crate::errors::ForensicError;

#[derive(Debug, Clone, Default)]
pub struct TpmInformation {
    pub version: String,
    pub manufacturer_id: u32,
    pub manufacturer_name: String,
    pub tpm_model: String,
    pub tpm_revision: String,
    pub status: TpmStatus,
}

#[derive(Debug, Clone, Default)]
pub enum TpmStatus {
    #[default]
    Ready,
    NotReady,
    Disabled,
    Enabled,
}

pub fn get_tpm_status() -> Result<TpmInformation, ForensicError> {
    Ok(TpmInformation {
        version: "2.0".to_string(),
        manufacturer_id: 0,
        manufacturer_name: "".to_string(),
        tpm_model: "".to_string(),
        tpm_revision: "".to_string(),
        status: TpmStatus::Ready,
    })
}

pub fn get_tpm_attestation() -> Result<TpmAttestation, ForensicError> {
    Ok(TpmAttestation {
        platform_credential: None,
        attestation_identity_key: None,
        endorsement_key: None,
    })
}

#[derive(Debug, Clone, Default)]
pub struct TpmAttestation {
    pub platform_credential: Option<Vec<u8>>,
    pub attestation_identity_key: Option<Vec<u8>>,
    pub endorsement_key: Option<Vec<u8>>,
}

pub fn get_tpm_supported_features() -> Result<TpmFeatures, ForensicError> {
    Ok(TpmFeatures {
        crypto_padding: true,
        algorithm_rsa: true,
        algorithm_ecc: true,
        key_storage: true,
        biometrics: false,
    })
}

#[derive(Debug, Clone, Default)]
pub struct TpmFeatures {
    pub crypto_padding: bool,
    pub algorithm_rsa: bool,
    pub algorithm_ecc: bool,
    pub key_storage: bool,
    pub biometrics: bool,
}

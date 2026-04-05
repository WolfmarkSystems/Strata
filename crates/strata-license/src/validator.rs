use crate::error::{LicenseError, Result};
use crate::fingerprint::machine_id_matches;
use crate::license::StrataLicense;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use std::fs;
use std::path::Path;

const TEST_SIGNING_KEY: [u8; 32] = [
    0x11, 0x42, 0x67, 0x13, 0x9A, 0x24, 0xF0, 0x35, 0x01, 0xBB, 0xCD, 0x55, 0x19, 0xAF, 0xE2, 0x44,
    0x0A, 0x90, 0x21, 0x3C, 0xDE, 0xFA, 0x77, 0x88, 0x10, 0x66, 0x6B, 0x52, 0x9E, 0x2F, 0xB4, 0xC8,
];

#[derive(Debug, Clone)]
pub struct LicenseValidator {
    public_key: VerifyingKey,
}

impl Default for LicenseValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenseValidator {
    pub fn new() -> Self {
        // PLACEHOLDER: replace with Wolfmark Systems production public key.
        // This test key keeps validation offline-capable during development.
        let signing_key = SigningKey::from_bytes(&TEST_SIGNING_KEY);
        Self {
            public_key: signing_key.verifying_key(),
        }
    }

    pub fn validate(&self, license_path: &Path) -> Result<StrataLicense> {
        let raw =
            fs::read_to_string(license_path).map_err(|err| LicenseError::Io(err.to_string()))?;
        let license = serde_json::from_str::<StrataLicense>(&raw)
            .map_err(|_| LicenseError::MalformedLicense)?;

        let signature_bytes = STANDARD
            .decode(license.signature.as_bytes())
            .map_err(|_| LicenseError::MalformedLicense)?;
        let signature = Signature::try_from(signature_bytes.as_slice())
            .map_err(|_| LicenseError::MalformedLicense)?;

        let payload = license
            .signing_payload()
            .map_err(|_| LicenseError::MalformedLicense)?;

        self.public_key
            .verify(&payload, &signature)
            .map_err(|_| LicenseError::InvalidSignature)?;

        if let Some(expires_at) = license.expires_at
            && expires_at <= Utc::now()
        {
            return Err(LicenseError::Expired);
        }

        if !machine_id_matches(&license.machine_id) {
            return Err(LicenseError::MachineMismatch);
        }

        Ok(license)
    }

    pub fn has_feature(&self, license: &StrataLicense, feature: &str) -> bool {
        license.features.iter().any(|item| item == feature)
    }

    pub fn days_remaining(license: &StrataLicense) -> Option<i64> {
        let expires = license.expires_at?;
        let remaining_seconds = (expires - Utc::now()).num_seconds();
        if remaining_seconds <= 0 {
            return Some(0);
        }

        let days = (remaining_seconds + 86_399) / 86_400;
        Some(days)
    }
}

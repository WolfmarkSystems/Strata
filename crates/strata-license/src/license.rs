use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LicenseTier {
    Free,
    Trial,
    Professional,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StrataLicense {
    pub license_id: String,
    pub product: String,
    pub tier: LicenseTier,
    pub licensee_name: String,
    pub licensee_org: String,
    pub machine_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub features: Vec<String>,
    pub signature: String,
}

impl StrataLicense {
    pub fn signing_payload(&self) -> std::result::Result<Vec<u8>, serde_json::Error> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_json::to_vec(&unsigned)
    }
}

mod error;
mod fingerprint;
mod free_tier;
mod license;
mod trial;
mod validator;

pub use error::LicenseError;
pub use fingerprint::{generate_machine_id, machine_id_matches};
pub use free_tier::{ENTERPRISE_FEATURES, FREE_FEATURES, PRO_FEATURES, TRIAL_FEATURES};
pub use license::{LicenseTier, StrataLicense};
pub use trial::{TrialState, get_trial_state, is_trial_expired, start_trial, trial_days_remaining};
pub use validator::LicenseValidator;

#[cfg(test)]
mod tests;

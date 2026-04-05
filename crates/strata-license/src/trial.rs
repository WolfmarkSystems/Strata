use crate::error::{LicenseError, Result};
use crate::fingerprint::generate_machine_id;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrialState {
    pub machine_id: String,
    pub product: String,
    pub trial_start: DateTime<Utc>,
    pub trial_days: u32,
}

pub fn start_trial(product: &str, days: u32) -> Result<TrialState> {
    let machine_id = generate_machine_id()?;
    let trial_days = if days == 0 { 30 } else { days };

    let state = TrialState {
        machine_id,
        product: product.to_string(),
        trial_start: Utc::now(),
        trial_days,
    };

    save_trial_state(&state)?;
    Ok(state)
}

pub fn get_trial_state(product: &str) -> Result<Option<TrialState>> {
    let path = trial_path(product)?;
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&path).map_err(|err| LicenseError::Io(err.to_string()))?;
    let state = serde_json::from_str::<TrialState>(&raw)
        .map_err(|err| LicenseError::Serde(err.to_string()))?;

    Ok(Some(state))
}

pub fn trial_days_remaining(state: &TrialState) -> i64 {
    let elapsed_days = (Utc::now() - state.trial_start).num_days();
    let remaining = i64::from(state.trial_days) - elapsed_days;
    if remaining < 0 { 0 } else { remaining }
}

pub fn is_trial_expired(state: &TrialState) -> bool {
    trial_days_remaining(state) <= 0
}

fn save_trial_state(state: &TrialState) -> Result<()> {
    let path = trial_path(&state.product)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| LicenseError::Io(err.to_string()))?;
    }

    let payload =
        serde_json::to_string_pretty(state).map_err(|err| LicenseError::Serde(err.to_string()))?;
    fs::write(path, payload).map_err(|err| LicenseError::Io(err.to_string()))?;

    Ok(())
}

fn trial_path(product: &str) -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let appdata =
            std::env::var("APPDATA").map_err(|_| LicenseError::HardwareFingerprintFailed)?;
        let mut path = PathBuf::from(appdata);
        path.push("Strata");
        path.push(format!("trial_{}.json", sanitize_product(product)));
        Ok(path)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").map_err(|_| LicenseError::HardwareFingerprintFailed)?;
        let mut path = PathBuf::from(home);
        path.push(".config");
        path.push("strata");
        path.push(format!("trial_{}.json", sanitize_product(product)));
        Ok(path)
    }
}

fn sanitize_product(product: &str) -> String {
    let normalized = product.trim().to_ascii_lowercase();
    let mut output = String::with_capacity(normalized.len());
    for ch in normalized.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            output.push(ch);
        } else {
            output.push('_');
        }
    }

    if output.is_empty() {
        "unknown".to_string()
    } else {
        output
    }
}

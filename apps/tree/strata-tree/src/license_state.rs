use chrono::{DateTime, Utc};
use std::fs;
use std::path::{Path, PathBuf};
use strata_license::{
    generate_machine_id, get_trial_state, trial_days_remaining, LicenseTier, LicenseValidator,
    StrataLicense, ENTERPRISE_FEATURES, FREE_FEATURES, PRO_FEATURES, TRIAL_FEATURES,
};

#[derive(Debug, Clone)]
pub struct AppLicenseState {
    pub tier: LicenseTier,
    pub features: Vec<String>,
    pub days_remaining: Option<i64>,
    pub license_path: Option<PathBuf>,
    pub is_trial: bool,
    pub trial_days_remaining: Option<i64>,
    licensee_name: Option<String>,
    licensee_org: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    machine_id: Option<String>,
    validation_error: Option<String>,
}

impl AppLicenseState {
    pub fn load() -> Self {
        let machine_id = generate_machine_id().ok();
        let validator = LicenseValidator::new();
        let mut last_validation_error: Option<String> = None;

        for candidate in license_candidates() {
            if !candidate.exists() {
                continue;
            }

            match validator.validate(&candidate) {
                Ok(license) => {
                    return Self::from_license(license, Some(candidate), machine_id.clone());
                }
                Err(err) => {
                    last_validation_error = Some(err.to_string());
                }
            }
        }

        if let Ok(Some(trial)) = get_trial_state("strata") {
            let remaining = trial_days_remaining(&trial).max(0);
            if remaining > 0 {
                return Self {
                    tier: LicenseTier::Trial,
                    features: TRIAL_FEATURES.iter().map(|f| (*f).to_string()).collect(),
                    days_remaining: Some(remaining),
                    license_path: None,
                    is_trial: true,
                    trial_days_remaining: Some(remaining),
                    licensee_name: Some("Trial User".to_string()),
                    licensee_org: None,
                    expires_at: Some(Utc::now() + chrono::Duration::days(remaining)),
                    machine_id,
                    validation_error: last_validation_error,
                };
            }

            return Self {
                tier: LicenseTier::Free,
                features: FREE_FEATURES.iter().map(|f| (*f).to_string()).collect(),
                days_remaining: Some(0),
                license_path: None,
                is_trial: true,
                trial_days_remaining: Some(0),
                licensee_name: None,
                licensee_org: None,
                expires_at: None,
                machine_id,
                validation_error: last_validation_error,
            };
        }

        Self {
            tier: LicenseTier::Free,
            features: FREE_FEATURES.iter().map(|f| (*f).to_string()).collect(),
            days_remaining: None,
            license_path: None,
            is_trial: false,
            trial_days_remaining: None,
            licensee_name: None,
            licensee_org: None,
            expires_at: None,
            machine_id,
            validation_error: last_validation_error,
        }
    }

    /// Create a dev-bypass license state (compile-time only, never in release).
    #[cfg(feature = "dev-bypass")]
    pub fn dev_bypass() -> Self {
        Self {
            tier: LicenseTier::Professional,
            features: vec![
                "file_carving".to_string(),
                "report_export".to_string(),
                "hash_sets".to_string(),
                "plugins".to_string(),
                "timeline".to_string(),
                "content_search".to_string(),
            ],
            days_remaining: Some(999),
            license_path: None,
            is_trial: false,
            trial_days_remaining: None,
            licensee_name: Some("DEV MODE".to_string()),
            licensee_org: Some("Wolfmark Systems".to_string()),
            expires_at: None,
            machine_id: None,
            validation_error: None,
        }
    }

    pub fn has_feature(&self, _feature: &str) -> bool {
        // During development: all features unlocked.
        // TODO: restore feature gating when licensing is shipped.
        true
    }

    pub fn is_trial_expired(&self) -> bool {
        self.is_trial && self.trial_days_remaining.unwrap_or(0) <= 0
    }

    pub fn display_status(&self) -> String {
        if self.is_trial_expired() {
            return "Trial Expired — Purchase required".to_string();
        }

        if self.is_trial {
            let days = self.trial_days_remaining.unwrap_or(0);
            return format!("Trial — {} days remaining", days);
        }

        match self.tier {
            LicenseTier::Professional => {
                let licensee = self
                    .licensee_name
                    .as_deref()
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or("Unknown licensee");
                format!("Professional License — Licensed to {}", licensee)
            }
            LicenseTier::Enterprise => {
                let licensee = self
                    .licensee_name
                    .as_deref()
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or("Unknown licensee");
                format!("Enterprise License — Licensed to {}", licensee)
            }
            LicenseTier::Trial => {
                let days = self.days_remaining.unwrap_or(0);
                format!("Trial — {} days remaining", days)
            }
            LicenseTier::Free => "Free Tier — Upgrade for full access".to_string(),
        }
    }

    pub fn machine_id_display(&self) -> String {
        self.machine_id
            .clone()
            .unwrap_or_else(|| "Unavailable".to_string())
    }

    pub fn expiry_display(&self) -> String {
        if self.is_trial_expired() {
            return "Expired".to_string();
        }

        if let Some(exp) = self.expires_at {
            return exp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        }

        match self.days_remaining {
            Some(days) => format!("{} days remaining", days.max(0)),
            None => "Perpetual".to_string(),
        }
    }

    pub fn licensee_display(&self) -> String {
        let name = self
            .licensee_name
            .as_deref()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or("-");
        let org = self
            .licensee_org
            .as_deref()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or("-");
        format!("{} ({})", name, org)
    }

    pub fn tier_short_label(&self) -> String {
        if self.is_trial_expired() {
            return "Expired".to_string();
        }
        if self.is_trial {
            return format!("Trial ({})", self.trial_days_remaining.unwrap_or(0));
        }

        match self.tier {
            LicenseTier::Free => "Free".to_string(),
            LicenseTier::Trial => format!("Trial ({})", self.days_remaining.unwrap_or(0)),
            LicenseTier::Professional => "Pro".to_string(),
            LicenseTier::Enterprise => "Enterprise".to_string(),
        }
    }

    pub fn validation_error(&self) -> Option<&str> {
        self.validation_error.as_deref()
    }

    pub fn appdata_license_path() -> Option<PathBuf> {
        let appdata = std::env::var("APPDATA").ok()?;
        let mut path = PathBuf::from(appdata);
        path.push("Strata");
        path.push("license.vlic");
        Some(path)
    }

    pub fn install_license_file(source: &Path) -> Result<Self, String> {
        let destination = Self::appdata_license_path()
            .ok_or_else(|| "APPDATA path is unavailable".to_string())?;

        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("Failed to prepare license directory: {}", err))?;
        }

        fs::copy(source, &destination)
            .map_err(|err| format!("Failed to copy license file: {}", err))?;

        let validator = LicenseValidator::new();
        validator
            .validate(&destination)
            .map_err(|err| format!("License validation failed: {}", err))?;

        Ok(Self::load())
    }

    fn from_license(
        license: StrataLicense,
        path: Option<PathBuf>,
        machine_id: Option<String>,
    ) -> Self {
        let days_remaining = LicenseValidator::days_remaining(&license);
        let (is_trial, trial_days_remaining) = if license.tier == LicenseTier::Trial {
            (true, days_remaining)
        } else {
            (false, None)
        };

        let features = if !license.features.is_empty() {
            license.features.clone()
        } else {
            match license.tier {
                LicenseTier::Free => FREE_FEATURES.iter().map(|f| (*f).to_string()).collect(),
                LicenseTier::Trial => TRIAL_FEATURES.iter().map(|f| (*f).to_string()).collect(),
                LicenseTier::Professional => {
                    PRO_FEATURES.iter().map(|f| (*f).to_string()).collect()
                }
                LicenseTier::Enterprise => ENTERPRISE_FEATURES
                    .iter()
                    .map(|f| (*f).to_string())
                    .collect(),
            }
        };

        Self {
            tier: license.tier,
            features,
            days_remaining,
            license_path: path,
            is_trial,
            trial_days_remaining,
            licensee_name: Some(license.licensee_name),
            licensee_org: Some(license.licensee_org),
            expires_at: license.expires_at,
            machine_id,
            validation_error: None,
        }
    }
}

fn license_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(path) = AppLicenseState::appdata_license_path() {
        out.push(path);
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            out.push(parent.join("license.vlic"));
        }
    }

    out
}

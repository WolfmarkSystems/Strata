//! Examiner profile persistence in %APPDATA%/Strata/examiner.json.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExaminerProfile {
    pub name: String,
    pub agency: String,
    #[serde(default, alias = "badge")]
    pub badge_number: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    pub saved_utc: String,
}

pub fn load_examiner_profile() -> Option<ExaminerProfile> {
    let path = profile_path();
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice::<ExaminerProfile>(&bytes).ok()
}

pub fn save_examiner_profile_full(
    name: &str,
    agency: &str,
    badge: &str,
    email: Option<&str>,
    timezone: Option<&str>,
) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let profile = ExaminerProfile {
        name: name.trim().to_string(),
        agency: agency.trim().to_string(),
        badge_number: badge.trim().to_string(),
        email: email
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
        timezone: timezone
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(default_timezone),
        saved_utc: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    let data = serde_json::to_vec_pretty(&profile).map_err(|e| e.to_string())?;
    std::fs::write(path, data).map_err(|e| e.to_string())
}

pub fn config_path() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        return PathBuf::from(appdata).join("Strata").join("examiner.json");
    }
    PathBuf::from("examiner.json")
}

fn profile_path() -> PathBuf {
    config_path()
}

fn default_timezone() -> String {
    "UTC".to_string()
}

// case/manager.rs — High-level case open/create operations.

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::project::VtpProject;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentCase {
    pub name: String,
    pub path: String,
    pub opened_utc: String,
}

pub struct CaseManager;

impl CaseManager {
    /// Create a new .vtp case file.
    pub fn new_case(
        name: &str,
        examiner: &str,
        output_path: impl AsRef<Path>,
    ) -> Result<VtpProject> {
        let output = output_path.as_ref();
        let project = VtpProject::create(output, name, examiner)?;
        record_recent_case(name, output.to_string_lossy().as_ref());
        Ok(project)
    }

    /// Open an existing .vtp file.
    pub fn open_case(path: impl AsRef<Path>) -> Result<VtpProject> {
        let path_ref = path.as_ref();
        let project = VtpProject::open(path_ref)?;
        let name = path_ref
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Case")
            .to_string();
        record_recent_case(&name, path_ref.to_string_lossy().as_ref());
        Ok(project)
    }

    /// Returns a list of recently opened cases from persisted state.
    pub fn recent_cases() -> Vec<RecentCase> {
        load_recent_cases()
    }
}

fn record_recent_case(name: &str, path: &str) {
    let mut list = load_recent_cases();
    list.retain(|c| !c.path.eq_ignore_ascii_case(path));
    list.insert(
        0,
        RecentCase {
            name: name.to_string(),
            path: path.to_string(),
            opened_utc: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        },
    );
    if list.len() > 20 {
        list.truncate(20);
    }
    if let Some(parent) = recent_cases_path().parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(&list) {
        let _ = std::fs::write(recent_cases_path(), bytes);
    }
}

fn load_recent_cases() -> Vec<RecentCase> {
    let path = recent_cases_path();
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    serde_json::from_slice::<Vec<RecentCase>>(&bytes)
        .ok()
        .unwrap_or_default()
}

fn recent_cases_path() -> std::path::PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        return std::path::PathBuf::from(appdata)
            .join("Strata")
            .join("recent_cases.json");
    }
    std::path::PathBuf::from("recent_cases.json")
}

use std::path::PathBuf;

use super::recentdocs::{get_recent_docs_location, parse_recent_docs};

pub fn get_recent_files() -> Vec<RecentFile> {
    let user_profile = std::env::var("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\Users\\Default"));
    let Some(recent_path) = get_recent_docs_location(&user_profile) else {
        return Vec::new();
    };
    let user_name = user_profile
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let Ok(history) = parse_recent_docs(&recent_path, &user_name) else {
        return Vec::new();
    };

    history
        .documents
        .into_iter()
        .map(|doc| RecentFile {
            path: doc.target_path.unwrap_or(doc.name),
            access_time: doc.accessed_time.unwrap_or(0).max(0) as u64,
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct RecentFile {
    pub path: String,
    pub access_time: u64,
}

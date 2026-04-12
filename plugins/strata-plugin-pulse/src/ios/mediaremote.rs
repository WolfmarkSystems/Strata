//! iOS MediaRemote — `com.apple.mediaremoted/` now-playing history.
//!
//! Records every song/podcast/video played via any app with
//! artist, title, and playback timestamps. High forensic value —
//! proves the user was consuming specific media at specific times.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "mediaremote") && {
        let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite") || n.ends_with(".plist")
    }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let source = path.to_string_lossy().to_string();
    let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();

    if n.ends_with(".db") || n.ends_with(".sqlite") {
        if let Some(conn) = util::open_sqlite_ro(path) {
            let tables: Vec<String> = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                .and_then(|mut s| { let r = s.query_map([], |row| row.get::<_, String>(0))?; Ok(r.flatten().collect()) })
                .unwrap_or_default();
            if !tables.is_empty() {
                let mut total = 0_i64;
                for t in &tables { total += util::count_rows(&conn, t); }
                return vec![ArtifactRecord {
                    category: ArtifactCategory::UserActivity,
                    subcategory: "MediaRemote".to_string(), timestamp: None,
                    title: "iOS now-playing / media playback history".to_string(),
                    detail: format!("{} rows — song/podcast/video titles, artists, playback times", total),
                    source_path: source, forensic_value: ForensicValue::High,
                    mitre_technique: None, is_suspicious: false, raw_data: None,
                }];
            }
        }
        return Vec::new();
    }

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "MediaRemote".to_string(), timestamp: None,
        title: "iOS MediaRemote now-playing plist".to_string(),
        detail: format!("MediaRemote data ({} bytes) — recently played media metadata", size),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: None, is_suspicious: false, raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn matches_mediaremote() {
        assert!(matches(Path::new("/var/mobile/Library/MediaRemote/store.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_plist() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("MediaRemote");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("state.plist");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("MediaRemote");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("state.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}

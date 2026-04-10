//! Spotify iOS — `offline.bnk`, `persistent_cache`, `*.db` under Spotify.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    if !util::path_contains(path, "spotify") { return false; }
    let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
    n == "offline.bnk" || n == "persistent_cache.db" || n == "recently_played.db"
        || n.ends_with(".db") || n.ends_with(".sqlite")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Try SQLite first
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
                subcategory: "Spotify".to_string(),
                timestamp: None,
                title: format!("Spotify iOS: {}", name),
                detail: format!("{} rows across {} tables in {}", total, tables.len(), name),
                source_path: source,
                forensic_value: ForensicValue::Medium,
                mitre_technique: None,
                is_suspicious: false,
                raw_data: None,
            }];
        }
    }

    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Spotify".to_string(),
        timestamp: None,
        title: format!("Spotify iOS: {}", name),
        detail: format!("{} ({} bytes)", name, size),
        source_path: source,
        forensic_value: ForensicValue::Medium,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_spotify_files() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/Caches/Spotify/offline.bnk")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_binary_file() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("spotify");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("offline.bnk");
        std::fs::write(&p, b"binary content").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("bytes"));
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("spotify");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("offline.bnk");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}

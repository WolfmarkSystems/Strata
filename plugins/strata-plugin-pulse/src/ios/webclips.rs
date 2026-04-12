//! iOS WebClips — home screen web shortcuts.
//!
//! Each `.webclip` bundle under `Library/WebClips/` contains an
//! `Info.plist` with URL, title, and icon. Shows sites user accessed
//! frequently enough to pin to the home screen.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["info.plist"]) && util::path_contains(path, "/webclips/")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    // Extract the webclip bundle name from path (e.g. "ABCD1234.webclip")
    let clip_name = path.parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    vec![ArtifactRecord {
        category: ArtifactCategory::WebActivity,
        subcategory: "WebClip".to_string(),
        timestamp: None,
        title: format!("Home screen web shortcut: {}", clip_name),
        detail: format!("WebClip Info.plist at {} ({} bytes) — pinned website URL + title", source, size),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_webclip_info_plist() {
        assert!(matches(Path::new("/var/mobile/Library/WebClips/ABCD1234.webclip/Info.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/Preferences/Info.plist")));
    }

    #[test]
    fn parses_clip_name_from_path() {
        let dir = tempdir().unwrap();
        let clip = dir.path().join("Library").join("WebClips").join("test.webclip");
        std::fs::create_dir_all(&clip).unwrap();
        let p = clip.join("Info.plist");
        std::fs::write(&p, b"bplist00fake").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].title.contains("test.webclip"));
    }

    #[test]
    fn empty_plist_returns_empty() {
        let dir = tempdir().unwrap();
        let clip = dir.path().join("Library").join("WebClips").join("x.webclip");
        std::fs::create_dir_all(&clip).unwrap();
        let p = clip.join("Info.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}

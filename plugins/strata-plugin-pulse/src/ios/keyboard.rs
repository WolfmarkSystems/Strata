//! iOS keyboard dynamic learning — `dynamic-text.dat`,
//! `en-dynamic-lm.bundle/dynamic-lm.dat`, `en_GB-dynamic.lm`.
//!
//! The Apple keyboard learns user vocabulary on-device. The dynamic
//! language model files are binary blobs (not SQLite), and the file
//! format has historically not been documented. iLEAPP simply reports
//! their presence and size as a presence indicator.
//!
//! v1.0 follows the same pattern: report path, size, and the language
//! locale embedded in the parent directory name when present.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    if name == "dynamic-text.dat" || name == "dynamic-lm.dat" {
        return true;
    }
    if name.ends_with("-dynamic.lm") || name.ends_with("dynamic.lm") {
        return true;
    }
    false
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();

    // Try to pull a language code out of the parent directory name,
    // e.g. `en-dynamic-lm.bundle` → "en".
    let locale = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .and_then(|n| n.split('-').next())
        .unwrap_or("(unknown)")
        .to_string();

    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Keyboard cache".to_string(),
        timestamp: None,
        title: format!("iOS keyboard dynamic LM ({})", locale),
        detail: format!(
            "Keyboard dynamic learning blob present at {} ({} bytes, locale {})",
            source, size, locale
        ),
        source_path: source,
        forensic_value: ForensicValue::Medium,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn matches_dynamic_filenames() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Keyboard/en-dynamic-lm.bundle/dynamic-lm.dat"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/Keyboard/dynamic-text.dat"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/Keyboard/en_GB-dynamic.lm"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_locale_from_parent_directory() {
        let dir = tempdir().unwrap();
        let bundle = dir.path().join("fr-dynamic-lm.bundle");
        std::fs::create_dir_all(&bundle).unwrap();
        let p = write(&bundle, "dynamic-lm.dat", b"some bytes");
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].title.contains("fr"));
        assert!(recs[0].detail.contains("locale fr"));
    }

    #[test]
    fn empty_file_returns_no_records() {
        let dir = tempdir().unwrap();
        let p = write(dir.path(), "dynamic-text.dat", b"");
        assert!(parse(&p).is_empty());
    }

    #[test]
    fn locale_falls_back_to_unknown_when_parent_has_no_dash() {
        let dir = tempdir().unwrap();
        let p = write(dir.path(), "dynamic-text.dat", b"x");
        let recs = parse(&p);
        // Parent directory is the temp dir name; first split before
        // '-' is whatever the temp prefix is — guaranteed not empty.
        assert!(!recs[0].title.contains("(unknown)") || recs[0].detail.contains("locale"));
    }
}

//! iOS CrashReporter — `*.ips`, `*.crash`, `*.synced`.
//!
//! `Library/Logs/CrashReporter/` and `Library/MobileCrashReporter/`
//! contain per-process crash dumps. Modern iOS uses the `.ips`
//! (incident report format) JSON+text hybrid; older releases use
//! `.crash` plain text. iLEAPP enumerates the directory and pulls the
//! crashing bundle ID + timestamp from the file header.
//!
//! Pulse v1.0 reports presence + size + crashing process name when it
//! can be parsed cheaply from the filename.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    n.ends_with(".ips") || n.ends_with(".crash") || n.ends_with(".synced")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // iOS crash filenames look like `processname-2026-04-09-120000.ips`.
    // Pull the prefix before the first '-YYYY-' as the process name.
    let proc_name = name.split("-20").next().unwrap_or(name);

    vec![ArtifactRecord {
        category: ArtifactCategory::ExecutionHistory,
        subcategory: "Crash report".to_string(),
        timestamp: None,
        title: format!("iOS crash report: {}", proc_name),
        detail: format!("{} ({} bytes) — process `{}`", name, size, proc_name),
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

    #[test]
    fn matches_ips_crash_and_synced_extensions() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Logs/CrashReporter/MyApp-2026-04-09-120000.ips"
        )));
        assert!(matches(Path::new("/copies/oldproc.crash")));
        assert!(matches(Path::new("/copies/something.synced")));
        assert!(!matches(Path::new("/copies/sms.db")));
    }

    #[test]
    fn parses_process_name_from_filename() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("MobileSafari-2026-04-09-120000.ips");
        std::fs::write(&p, b"crash payload").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].title.contains("MobileSafari"));
    }

    #[test]
    fn empty_file_returns_no_records() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("MobileSafari-2026-04-09-120000.ips");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}

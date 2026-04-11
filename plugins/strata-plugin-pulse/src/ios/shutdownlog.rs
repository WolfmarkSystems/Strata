//! iOS shutdown log — `shutdown.log`.
//!
//! Records device shutdowns with timestamps and process states.
//! Gaps in uptime and unusual shutdown times are forensically
//! significant (e.g. device powered off during a crime window).

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
    n == "shutdown.log"
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    if text.trim().is_empty() { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    let line_count = text.lines().count();
    // Count lines containing "SIGTERM" — each is a shutdown event
    let shutdown_count = text.lines()
        .filter(|l| l.to_ascii_uppercase().contains("SIGTERM") || l.contains("remaining"))
        .count();
    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "Shutdown log".to_string(),
        timestamp: None,
        title: "iOS shutdown log".to_string(),
        detail: format!("{} lines, ~{} shutdown events — device power-off history", line_count, shutdown_count),
        source_path: source,
        forensic_value: ForensicValue::High,
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
    fn matches_shutdown_log() {
        assert!(matches(Path::new("/var/log/shutdown.log")));
        assert!(!matches(Path::new("/var/log/syslog")));
    }

    #[test]
    fn parses_line_and_event_count() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("shutdown.log");
        std::fs::write(&p, "Mon Apr 10 12:00:00 2026 SIGTERM: [SpringBoard]\nMon Apr 10 12:00:01 2026 remaining\n").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("2 lines"));
        assert!(recs[0].detail.contains("~2 shutdown"));
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("shutdown.log");
        std::fs::write(&p, "").unwrap();
        assert!(parse(&p).is_empty());
    }
}

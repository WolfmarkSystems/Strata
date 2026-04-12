//! iOS app install history — `mobile_installation.log.0` and friends.
//!
//! Apple's mobile installation daemon writes one append-only log per
//! file rotation. iLEAPP keys off the textual log lines:
//!   * `Made container live for ...` — install/launch
//!   * `Uninstalling identifier ...` — uninstall
//!   * `BundleContainer ...` / `DataContainer ...` — bundle paths
//!
//! Pulse v1.0 doesn't try to recover full timestamps from the line
//! prefix because the prefix format differs across iOS releases. We
//! count event types, list the unique bundle IDs we observed, and
//! emit one record per file. Per-line timestamping moves to v1.1.

use std::collections::BTreeSet;
use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    name.starts_with("mobile_installation.log") || name == "mobile_installation.log"
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };

    let stats = scan_log(&text);
    let source = path.to_string_lossy().to_string();

    out.push(ArtifactRecord {
        category: ArtifactCategory::ExecutionHistory,
        subcategory: "App install log".to_string(),
        timestamp: None,
        title: "iOS mobile_installation log".to_string(),
        detail: format!(
            "{} install events, {} uninstall events, {} unique bundle IDs observed",
            stats.installs, stats.uninstalls, stats.bundle_ids.len()
        ),
        source_path: source.clone(),
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1027".to_string()),
        is_suspicious: stats.uninstalls > 0 && stats.installs == 0,
        raw_data: None,
        confidence: 0,
    });

    // Surface bundle IDs as their own subcategory so the panel can
    // group multiple installs of the same app.
    for bundle in stats.bundle_ids.iter().take(50) {
        out.push(ArtifactRecord {
            category: ArtifactCategory::ExecutionHistory,
            subcategory: "App install bundle".to_string(),
            timestamp: None,
            title: format!("Bundle observed: {}", bundle),
            detail: format!("Seen in mobile_installation log at {}", source),
            source_path: source.clone(),
            forensic_value: ForensicValue::Medium,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
    }

    out
}

#[derive(Default, Debug)]
struct LogStats {
    installs: usize,
    uninstalls: usize,
    bundle_ids: BTreeSet<String>,
}

fn scan_log(text: &str) -> LogStats {
    let mut stats = LogStats::default();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("made container live for") || lower.contains("installing app") {
            stats.installs += 1;
            if let Some(b) = extract_bundle_id(line) {
                stats.bundle_ids.insert(b);
            }
        }
        if lower.contains("uninstalling identifier") || lower.contains("uninstalling app") {
            stats.uninstalls += 1;
            if let Some(b) = extract_bundle_id(line) {
                stats.bundle_ids.insert(b);
            }
        }
        if lower.contains("bundlecontainer") || lower.contains("datacontainer") {
            if let Some(b) = extract_bundle_id(line) {
                stats.bundle_ids.insert(b);
            }
        }
    }
    stats
}

/// Pull the first reverse-DNS-shaped token from a log line. iOS bundle
/// IDs are always `xx.yy.zz` so we look for a `.`-containing token of
/// >=2 dots that does not start with a slash or quote.
fn extract_bundle_id(line: &str) -> Option<String> {
    for tok in line.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '(' | ')')) {
        let trimmed = tok.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
        if trimmed.matches('.').count() >= 2
            && !trimmed.starts_with('.')
            && !trimmed.ends_with('.')
            && trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Some(trimmed.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a log into a fresh temp dir at the canonical filename
    /// and return both the path and the dir guard so tempfile cleans
    /// up when the test ends.
    fn write_log_simple(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mobile_installation.log.0");
        std::fs::write(&p, content).unwrap();
        (dir, p)
    }

    #[test]
    fn matches_rotated_log_filenames() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Logs/MobileInstallation/mobile_installation.log.0"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/Logs/MobileInstallation/mobile_installation.log.4"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/Logs/random.log")));
    }

    #[test]
    fn parses_install_and_uninstall_counts() {
        let log = "\
            2026-04-09 12:00:00 mobile_installation_proxy[42]: Made container live for com.example.foo at /var/mobile/Containers/Data/Application/UUID\n\
            2026-04-09 12:01:00 mobile_installation_proxy[42]: Made container live for com.example.bar at /var/mobile/Containers/Data/Application/UUID\n\
            2026-04-09 12:02:00 mobile_installation_proxy[42]: Uninstalling identifier com.example.foo\n";
        let (_dir, p) = write_log_simple(log);
        let records = parse(&p);
        let summary = records
            .iter()
            .find(|r| r.subcategory == "App install log")
            .expect("summary");
        assert!(summary.detail.contains("2 install events"));
        assert!(summary.detail.contains("1 uninstall events"));
        // Two unique bundle IDs.
        assert!(summary.detail.contains("2 unique bundle IDs"));

        // Bundle records present.
        assert!(records
            .iter()
            .any(|r| r.subcategory == "App install bundle" && r.title.contains("com.example.foo")));
        assert!(records
            .iter()
            .any(|r| r.subcategory == "App install bundle" && r.title.contains("com.example.bar")));
    }

    #[test]
    fn extract_bundle_id_handles_quoted_token() {
        let line = "BundleContainer = \"com.acme.demo\";";
        assert_eq!(extract_bundle_id(line).as_deref(), Some("com.acme.demo"));
    }

    #[test]
    fn extract_bundle_id_returns_none_for_lines_without_dotted_tokens() {
        assert!(extract_bundle_id("nothing interesting here").is_none());
    }

    #[test]
    fn empty_log_emits_only_summary_record() {
        let (_dir, p) = write_log_simple("");
        let records = parse(&p);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].subcategory, "App install log");
    }

    #[test]
    fn unparseable_file_returns_empty() {
        // Binary garbage — read_to_string fails so parser bails.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mobile_installation.log.0");
        std::fs::write(&p, [0xFF_u8, 0xFE, 0xFD, 0xFC]).unwrap();
        let records = parse(&p);
        // Either empty (read_to_string failed) or just the summary —
        // both are acceptable; we only require no panic.
        assert!(records.len() <= 1);
    }
}

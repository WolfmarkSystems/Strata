//! CHROMEOS-1 — ChromeOS-specific forensic artifacts.
//!
//! ChromeOS stashes user data under `/home/chronos/u-{hash}/` on the
//! stateful partition. This module walks the observable subset:
//! enterprise-enrollment policy files, the Chrome profile root
//! (delegated to the existing carbon parsers), the Crostini Linux VM
//! home (delegated to ARBOR's Linux parsers), and the Android app
//! container (delegated to carbon's Android parsers).
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChromeOSArtifact {
    pub artifact_type: String,
    pub account: Option<String>,
    pub enrollment_domain: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub event_data: String,
}

/// Detect ChromeOS by presence of the canonical paths.
pub fn is_chromeos_root(root: &Path) -> bool {
    let probes = ["home/chronos", "opt/google/chrome", "etc/cros-machine-id"];
    probes.iter().any(|p| root.join(p).exists())
}

/// Pull enterprise-enrollment metadata from the policy.json style
/// file many enterprise-enrolled Chromebooks keep on the stateful
/// partition. Returns the domain and whether the device is
/// enterprise-owned. Fails soft on missing / malformed files.
pub fn read_enrollment_info(json: &str) -> Option<(String, bool)> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let domain = v
        .get("enrollment_domain")
        .and_then(|x| x.as_str())
        .map(String::from)?;
    let enterprise = v
        .get("device_owner")
        .and_then(|x| x.as_str())
        .map(|s| s.eq_ignore_ascii_case("enterprise"))
        .unwrap_or(false);
    Some((domain, enterprise))
}

/// Enumerate ChromeOS user profiles living under `/home/chronos/`.
pub fn chronos_user_dirs(root: &Path) -> Vec<PathBuf> {
    let base = root.join("home/chronos");
    let Ok(entries) = std::fs::read_dir(&base) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_string_lossy().into_owned();
            if name == "user" || name.starts_with("u-") {
                Some(p)
            } else {
                None
            }
        })
        .collect()
}

/// Detect Crostini (Linux VM on ChromeOS) by presence of the VM
/// container directory. Delegates further parsing to arbor's existing
/// Linux modules.
pub fn has_crostini(root: &Path) -> bool {
    root.join("home/chronos/user/crostini").exists()
        || root
            .join("home/chronos/user/.local/share/crostini")
            .exists()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_chromeos_via_cros_machine_id() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("etc")).expect("mk");
        fs::write(tmp.path().join("etc/cros-machine-id"), b"abc").expect("w");
        assert!(is_chromeos_root(tmp.path()));
    }

    #[test]
    fn detects_chromeos_via_chronos_home() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("home/chronos")).expect("mk");
        assert!(is_chromeos_root(tmp.path()));
    }

    #[test]
    fn plain_linux_rejected() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("etc")).expect("mk");
        fs::write(tmp.path().join("etc/os-release"), b"NAME=Ubuntu").expect("w");
        assert!(!is_chromeos_root(tmp.path()));
    }

    #[test]
    fn read_enrollment_returns_domain_and_enterprise_flag() {
        let json = r#"{"enrollment_domain":"example.edu","device_owner":"enterprise"}"#;
        let (domain, ent) = read_enrollment_info(json).expect("parsed");
        assert_eq!(domain, "example.edu");
        assert!(ent);
    }

    #[test]
    fn read_enrollment_tolerates_missing_owner() {
        let json = r#"{"enrollment_domain":"school.org"}"#;
        let (domain, ent) = read_enrollment_info(json).expect("parsed");
        assert_eq!(domain, "school.org");
        assert!(!ent);
    }

    #[test]
    fn enumerates_chronos_user_dirs() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("home/chronos/u-abc123")).expect("mk");
        fs::create_dir_all(tmp.path().join("home/chronos/user")).expect("mk");
        let users = chronos_user_dirs(tmp.path());
        assert!(users.iter().any(|p| p.ends_with("u-abc123")));
        assert!(users.iter().any(|p| p.ends_with("user")));
    }

    #[test]
    fn detects_crostini_when_present() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("home/chronos/user/crostini")).expect("mk");
        assert!(has_crostini(tmp.path()));
    }
}

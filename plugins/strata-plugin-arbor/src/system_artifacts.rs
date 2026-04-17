//! Linux system artifacts: SSH, package manager, user accounts (LNX-4).
//!
//! MITRE: T1098.004, T1059.004, T1136.001, T1548.003.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::fs;
use std::path::Path;
use strata_plugin_sdk::Artifact;

const HACKING_PACKAGES: &[&str] = &[
    "nmap",
    "netcat",
    "ncat",
    "john",
    "hydra",
    "aircrack-ng",
    "metasploit-framework",
    "sqlmap",
    "nikto",
    "gobuster",
    "hashcat",
    "responder",
    "mimikatz",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSystemArtifact {
    pub category: String,
    pub artifact_type: String,
    pub username: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub value: String,
    pub suspicious_reason: Option<String>,
}

pub fn classify_path(path: &Path) -> Option<&'static str> {
    let lower = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    if name == "sshd_config" {
        return Some("SshdConfig");
    }
    if name == "authorized_keys" {
        return Some("AuthorizedKeys");
    }
    if name == "known_hosts" {
        return Some("KnownHosts");
    }
    if name == "config" && lower.contains("/.ssh/") {
        return Some("SshConfig");
    }
    if name == "passwd" && lower.contains("/etc/") {
        return Some("Passwd");
    }
    if name == "shadow" && lower.contains("/etc/") {
        return Some("Shadow");
    }
    if name == "sudoers" && lower.contains("/etc/") {
        return Some("Sudoers");
    }
    if lower.contains("/var/log/apt/history.log") || lower.contains("/var/log/dpkg.log") {
        return Some("PackageApt");
    }
    if lower.contains("/var/log/yum.log") || lower.contains("/var/log/dnf.log") {
        return Some("PackageYum");
    }
    if lower.contains("/var/log/pacman.log") {
        return Some("PackagePacman");
    }
    None
}

pub fn parse_sshd_config(body: &str) -> Vec<LinuxSystemArtifact> {
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let key = parts.next().unwrap_or("").to_ascii_lowercase();
        let value = parts.next().unwrap_or("").trim();
        let reason = match key.as_str() {
            "permitrootlogin" if value.eq_ignore_ascii_case("yes") => {
                Some("PermitRootLogin=yes")
            }
            "permitemptypasswords" if value.eq_ignore_ascii_case("yes") => {
                Some("PermitEmptyPasswords=yes")
            }
            "passwordauthentication" if value.eq_ignore_ascii_case("yes") => {
                Some("PasswordAuthentication=yes (no enforced restrictions)")
            }
            "port" if value != "22" => Some("non-standard SSH port"),
            _ => None,
        };
        if let Some(r) = reason {
            out.push(LinuxSystemArtifact {
                category: "SSH".into(),
                artifact_type: "SshdConfig".into(),
                username: None,
                timestamp: None,
                value: format!("{} {}", key, value),
                suspicious_reason: Some(r.to_string()),
            });
        }
    }
    out
}

pub fn parse_passwd(body: &str) -> Vec<LinuxSystemArtifact> {
    let mut out = Vec::new();
    for line in body.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 7 {
            continue;
        }
        let username = parts[0].to_string();
        let Ok(uid) = parts[2].parse::<u32>() else {
            continue;
        };
        let home = parts[5].to_string();
        let shell = parts[6].trim().to_string();
        let reason = if uid == 0 && username != "root" {
            Some("Non-root account with uid=0".to_string())
        } else if !shell.is_empty()
            && !shell.contains("/nologin")
            && !shell.contains("/false")
            && home.is_empty()
        {
            Some("Shell account with empty home directory".to_string())
        } else {
            None
        };
        if reason.is_some() {
            out.push(LinuxSystemArtifact {
                category: "UserAccount".into(),
                artifact_type: "Passwd".into(),
                username: Some(username.clone()),
                timestamp: None,
                value: format!("uid={} home={} shell={}", uid, home, shell),
                suspicious_reason: reason,
            });
        }
    }
    out
}

pub fn parse_sudoers(body: &str) -> Vec<LinuxSystemArtifact> {
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let lc = trimmed.to_ascii_lowercase();
        if lc.contains("all=(all) nopasswd: all") {
            out.push(LinuxSystemArtifact {
                category: "Sudoers".into(),
                artifact_type: "SudoersRule".into(),
                username: trimmed
                    .split_whitespace()
                    .next()
                    .map(|s| s.to_string()),
                timestamp: None,
                value: trimmed.to_string(),
                suspicious_reason: Some("unrestricted passwordless sudo".into()),
            });
        }
    }
    out
}

pub fn parse_authorized_keys(body: &str) -> Vec<LinuxSystemArtifact> {
    let mut out = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, char::is_whitespace).collect();
        let (key_type, comment) = match parts.as_slice() {
            [k, _pk] => (k.to_string(), None),
            [k, _pk, c] => (k.to_string(), Some(c.to_string())),
            _ => continue,
        };
        let reason = if comment.is_none() {
            Some("authorized_keys entry has no comment".to_string())
        } else {
            None
        };
        out.push(LinuxSystemArtifact {
            category: "SSH".into(),
            artifact_type: "AuthorizedKey".into(),
            username: None,
            timestamp: None,
            value: format!("#{} {} {}", idx + 1, key_type, comment.as_deref().unwrap_or("-")),
            suspicious_reason: reason,
        });
    }
    out
}

pub fn parse_apt_history(body: &str) -> Vec<LinuxSystemArtifact> {
    let mut out = Vec::new();
    let mut current_date: Option<String> = None;
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Start-Date: ") {
            current_date = Some(rest.to_string());
            continue;
        }
        for action in ["Install:", "Upgrade:", "Remove:", "Purge:"] {
            if let Some(rest) = trimmed.strip_prefix(action) {
                let action_label = action.trim_end_matches(':').to_string();
                let pkg_list: Vec<&str> = rest.split(',').collect();
                for pkg in pkg_list {
                    let raw = pkg.split_whitespace().next().unwrap_or("").trim();
                    if raw.is_empty() {
                        continue;
                    }
                    let name = raw.split(':').next().unwrap_or(raw);
                    let reason = if HACKING_PACKAGES.contains(&name) {
                        Some("hacking tool package".to_string())
                    } else {
                        None
                    };
                    out.push(LinuxSystemArtifact {
                        category: "Package".into(),
                        artifact_type: format!("Apt{}", action_label),
                        username: None,
                        timestamp: None,
                        value: format!(
                            "{} {} @ {}",
                            action_label,
                            name,
                            current_date.as_deref().unwrap_or("?")
                        ),
                        suspicious_reason: reason,
                    });
                }
            }
        }
    }
    out
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let Some(kind) = classify_path(path) else {
        return Vec::new();
    };
    let Ok(body) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let records = match kind {
        "SshdConfig" => parse_sshd_config(&body),
        "AuthorizedKeys" => parse_authorized_keys(&body),
        "Passwd" => parse_passwd(&body),
        "Sudoers" => parse_sudoers(&body),
        "PackageApt" => parse_apt_history(&body),
        _ => Vec::new(),
    };
    records
        .into_iter()
        .map(|r| {
            let mut a = Artifact::new("Linux System Artifact", &path.to_string_lossy());
            a.timestamp = r.timestamp.map(|d| d.timestamp() as u64);
            a.add_field(
                "title",
                &format!("{} {}: {}", r.category, r.artifact_type, r.value),
            );
            a.add_field("file_type", "Linux System Artifact");
            a.add_field("category", &r.category);
            a.add_field("artifact_type", &r.artifact_type);
            if let Some(u) = &r.username {
                a.add_field("username", u);
            }
            a.add_field("value", &r.value);
            let mitre = match r.category.as_str() {
                "SSH" => "T1098.004",
                "UserAccount" => "T1136.001",
                "Sudoers" => "T1548.003",
                _ => "T1059.004",
            };
            a.add_field("mitre", mitre);
            if let Some(reason) = &r.suspicious_reason {
                a.add_field("suspicious_reason", reason);
                a.add_field("suspicious", "true");
                a.add_field("forensic_value", "High");
            } else {
                a.add_field("forensic_value", "Low");
            }
            a
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recognises_system_artifacts() {
        assert_eq!(classify_path(Path::new("/etc/ssh/sshd_config")), Some("SshdConfig"));
        assert_eq!(classify_path(Path::new("/home/alice/.ssh/authorized_keys")), Some("AuthorizedKeys"));
        assert_eq!(classify_path(Path::new("/etc/passwd")), Some("Passwd"));
        assert_eq!(classify_path(Path::new("/etc/sudoers")), Some("Sudoers"));
        assert_eq!(classify_path(Path::new("/var/log/apt/history.log")), Some("PackageApt"));
        assert!(classify_path(Path::new("/tmp/other")).is_none());
    }

    #[test]
    fn parse_sshd_config_flags_insecure_settings() {
        let body = "PermitRootLogin yes\nPermitEmptyPasswords no\nPort 2222\n";
        let entries = parse_sshd_config(body);
        assert!(entries.iter().any(|e| e.value.starts_with("permitrootlogin")));
        assert!(entries.iter().any(|e| e.value.starts_with("port")));
    }

    #[test]
    fn parse_passwd_flags_uid_zero_non_root() {
        let body = "root:x:0:0:root:/root:/bin/bash\n\
                    ghost:x:0:0::/tmp:/bin/bash\n\
                    alice:x:1000:1000::/home/alice:/bin/bash\n";
        let entries = parse_passwd(body);
        assert!(entries
            .iter()
            .any(|e| e.username.as_deref() == Some("ghost")));
    }

    #[test]
    fn parse_sudoers_flags_unrestricted_rule() {
        let body = "alice ALL=(ALL) NOPASSWD: ALL\nbob ALL=(ALL) ALL\n";
        let entries = parse_sudoers(body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].username.as_deref(), Some("alice"));
    }

    #[test]
    fn parse_apt_history_flags_hacking_packages() {
        let body = "Start-Date: 2026-04-16  12:00:00\n\
                    Install: nmap:amd64 (7.94), netcat:amd64 (1.10)\n\
                    End-Date: 2026-04-16  12:00:05\n";
        let entries = parse_apt_history(body);
        assert!(entries
            .iter()
            .any(|e| e.suspicious_reason.as_deref() == Some("hacking tool package")));
    }

    #[test]
    fn parse_authorized_keys_flags_no_comment() {
        let body = "ssh-rsa AAAA... alice@host\nssh-rsa AAAA...\n";
        let entries = parse_authorized_keys(body);
        assert!(entries
            .iter()
            .any(|e| e.suspicious_reason.is_some()));
    }
}

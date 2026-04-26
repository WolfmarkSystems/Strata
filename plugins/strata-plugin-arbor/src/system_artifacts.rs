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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub username: String,
    pub password_field: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home_dir: String,
    pub shell: String,
    pub is_suspicious_uid_zero: bool,
    pub has_empty_password_field: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEntry {
    pub username: String,
    pub hash_algorithm: String,
    pub is_locked: bool,
    pub last_change_days: Option<i64>,
    pub has_no_expiry: bool,
    pub is_weak_algorithm: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcNetTcpEntry {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
}

pub fn classify_path(path: &Path) -> Option<&'static str> {
    let lower = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
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
    if name == "hosts" && lower.contains("/etc/") {
        return Some("Hosts");
    }
    if name == "tcp" && lower.contains("/proc/net/") {
        return Some("ProcNetTcp");
    }
    if name == "tcp6" && lower.contains("/proc/net/") {
        return Some("ProcNetTcp6");
    }
    if (name == "id_rsa" || name == "id_ed25519" || name == "id_ecdsa") && lower.contains("/.ssh/")
    {
        return Some("SshPrivateKey");
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
            "permitrootlogin" if value.eq_ignore_ascii_case("yes") => Some("PermitRootLogin=yes"),
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
        let Some(entry) = parse_passwd_line(line) else {
            continue;
        };
        let reason = if entry.is_suspicious_uid_zero {
            Some("Non-root account with uid=0".to_string())
        } else if entry.has_empty_password_field {
            Some("Empty passwd password field".to_string())
        } else if !entry.shell.is_empty()
            && !entry.shell.contains("/nologin")
            && !entry.shell.contains("/false")
            && entry.home_dir.is_empty()
        {
            Some("Shell account with empty home directory".to_string())
        } else {
            None
        };
        if reason.is_some() {
            out.push(LinuxSystemArtifact {
                category: "UserAccount".into(),
                artifact_type: "Passwd".into(),
                username: Some(entry.username.clone()),
                timestamp: None,
                value: format!(
                    "uid={} gid={} home={} shell={}",
                    entry.uid, entry.gid, entry.home_dir, entry.shell
                ),
                suspicious_reason: reason,
            });
        }
    }
    out
}

pub fn parse_passwd_line(line: &str) -> Option<PasswdEntry> {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 7 {
        return None;
    }
    let uid = parts.get(2)?.parse::<u32>().ok()?;
    let gid = parts.get(3)?.parse::<u32>().ok()?;
    let username = parts.first()?.to_string();
    let password_field = parts.get(1)?.to_string();
    Some(PasswdEntry {
        is_suspicious_uid_zero: uid == 0 && username != "root",
        has_empty_password_field: password_field.is_empty(),
        username,
        password_field,
        uid,
        gid,
        gecos: parts.get(4)?.to_string(),
        home_dir: parts.get(5)?.to_string(),
        shell: parts.get(6)?.trim().to_string(),
    })
}

pub fn parse_shadow_line(line: &str) -> Option<ShadowEntry> {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 2 {
        return None;
    }
    let username = parts.first()?.to_string();
    let hash = parts.get(1)?.trim();
    let is_locked = hash.starts_with('!') || hash.starts_with('*');
    let hash_algorithm = if hash.starts_with("$1$") {
        "MD5"
    } else if hash.starts_with("$5$") {
        "SHA256"
    } else if hash.starts_with("$6$") {
        "SHA512"
    } else if hash.is_empty() {
        "EMPTY"
    } else if is_locked {
        "LOCKED"
    } else {
        "UNKNOWN"
    };
    let max_age = parts.get(4).and_then(|v| v.parse::<i64>().ok());
    Some(ShadowEntry {
        username,
        hash_algorithm: hash_algorithm.to_string(),
        is_locked,
        last_change_days: parts.get(2).and_then(|v| v.parse::<i64>().ok()),
        has_no_expiry: max_age.is_none() || max_age == Some(99_999),
        is_weak_algorithm: hash_algorithm == "MD5" || hash_algorithm == "EMPTY",
    })
}

pub fn parse_shadow(body: &str) -> Vec<LinuxSystemArtifact> {
    body.lines()
        .filter_map(parse_shadow_line)
        .filter(|entry| entry.is_weak_algorithm || entry.has_no_expiry || !entry.is_locked)
        .map(|entry| {
            let mut reasons = Vec::new();
            if entry.is_weak_algorithm {
                reasons.push("weak password hash algorithm");
            }
            if entry.has_no_expiry {
                reasons.push("password has no expiry");
            }
            if !entry.is_locked {
                reasons.push("account hash is active");
            }
            LinuxSystemArtifact {
                category: "Credential".into(),
                artifact_type: "Shadow".into(),
                username: Some(entry.username.clone()),
                timestamp: None,
                value: format!(
                    "algorithm={} locked={} last_change_days={:?}",
                    entry.hash_algorithm, entry.is_locked, entry.last_change_days
                ),
                suspicious_reason: Some(reasons.join("; ")),
            }
        })
        .collect()
}

pub fn parse_hosts(body: &str) -> Vec<LinuxSystemArtifact> {
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = t.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let ip = parts[0];
        for host in &parts[1..] {
            let suspicious = (ip == "127.0.0.1" || ip == "0.0.0.0")
                && !host.eq_ignore_ascii_case("localhost")
                && !host.ends_with(".local");
            out.push(LinuxSystemArtifact {
                category: "Hosts".into(),
                artifact_type: "HostsEntry".into(),
                username: None,
                timestamp: None,
                value: format!("{ip} {host}"),
                suspicious_reason: suspicious.then(|| "domain redirected to localhost".to_string()),
            });
        }
    }
    out
}

pub fn parse_known_hosts(body: &str) -> Vec<LinuxSystemArtifact> {
    body.lines()
        .filter_map(|line| {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                return None;
            }
            let host = t.split_whitespace().next()?.to_string();
            Some(LinuxSystemArtifact {
                category: "SSH".into(),
                artifact_type: "KnownHost".into(),
                username: None,
                timestamp: None,
                value: host,
                suspicious_reason: None,
            })
        })
        .collect()
}

pub fn parse_proc_net_tcp_line(line: &str) -> Option<ProcNetTcpEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 || !fields.first()?.ends_with(':') {
        return None;
    }
    let (local_addr, local_port) = parse_proc_addr(fields.get(1)?)?;
    let (remote_addr, remote_port) = parse_proc_addr(fields.get(2)?)?;
    Some(ProcNetTcpEntry {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state: tcp_state_name(fields.get(3)?).to_string(),
    })
}

fn parse_proc_addr(value: &str) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = value.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if addr_hex.len() == 8 {
        let bytes = (0..4)
            .filter_map(|idx| u8::from_str_radix(&addr_hex[idx * 2..idx * 2 + 2], 16).ok())
            .collect::<Vec<_>>();
        if bytes.len() != 4 {
            return None;
        }
        return Some((
            format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]),
            port,
        ));
    }
    Some((addr_hex.to_string(), port))
}

fn tcp_state_name(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "0A" => "LISTEN",
        _ => "OTHER",
    }
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
                username: trimmed.split_whitespace().next().map(|s| s.to_string()),
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
            value: format!(
                "#{} {} {}",
                idx + 1,
                key_type,
                comment.as_deref().unwrap_or("-")
            ),
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
        "KnownHosts" => parse_known_hosts(&body),
        "Passwd" => parse_passwd(&body),
        "Shadow" => parse_shadow(&body),
        "Hosts" => parse_hosts(&body),
        "Sudoers" => parse_sudoers(&body),
        "PackageApt" => parse_apt_history(&body),
        "ProcNetTcp" | "ProcNetTcp6" => body
            .lines()
            .filter_map(parse_proc_net_tcp_line)
            .map(|entry| LinuxSystemArtifact {
                category: "Network".into(),
                artifact_type: "ProcNetTcp".into(),
                username: None,
                timestamp: None,
                value: format!(
                    "{}:{} -> {}:{} ({})",
                    entry.local_addr,
                    entry.local_port,
                    entry.remote_addr,
                    entry.remote_port,
                    entry.state
                ),
                suspicious_reason: None,
            })
            .collect(),
        "SshPrivateKey" => vec![LinuxSystemArtifact {
            category: "SSH".into(),
            artifact_type: "PrivateKey".into(),
            username: None,
            timestamp: None,
            value: "SSH private key present".to_string(),
            suspicious_reason: Some("private SSH key found on disk".to_string()),
        }],
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
                "Credential" => "T1003.008",
                "Hosts" => "T1565.001",
                "Network" => "T1049",
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
        assert_eq!(
            classify_path(Path::new("/etc/ssh/sshd_config")),
            Some("SshdConfig")
        );
        assert_eq!(
            classify_path(Path::new("/home/alice/.ssh/authorized_keys")),
            Some("AuthorizedKeys")
        );
        assert_eq!(classify_path(Path::new("/etc/passwd")), Some("Passwd"));
        assert_eq!(classify_path(Path::new("/etc/shadow")), Some("Shadow"));
        assert_eq!(classify_path(Path::new("/etc/hosts")), Some("Hosts"));
        assert_eq!(
            classify_path(Path::new("/proc/net/tcp")),
            Some("ProcNetTcp")
        );
        assert_eq!(classify_path(Path::new("/etc/sudoers")), Some("Sudoers"));
        assert_eq!(
            classify_path(Path::new("/var/log/apt/history.log")),
            Some("PackageApt")
        );
        assert!(classify_path(Path::new("/tmp/other")).is_none());
    }

    #[test]
    fn parse_sshd_config_flags_insecure_settings() {
        let body = "PermitRootLogin yes\nPermitEmptyPasswords no\nPort 2222\n";
        let entries = parse_sshd_config(body);
        assert!(entries
            .iter()
            .any(|e| e.value.starts_with("permitrootlogin")));
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
        assert!(entries.iter().any(|e| e.suspicious_reason.is_some()));
    }

    #[test]
    fn arbor_passwd_parses_root_entry() {
        let line = "root:x:0:0:root:/root:/bin/bash";
        let entry = parse_passwd_line(line).expect("passwd entry");
        assert_eq!(entry.username, "root");
        assert_eq!(entry.uid, 0);
    }

    #[test]
    fn arbor_passwd_flags_uid_zero_non_root() {
        let line = "backdoor:x:0:0::/tmp:/bin/bash";
        let entry = parse_passwd_line(line).expect("passwd entry");
        assert!(entry.is_suspicious_uid_zero);
    }

    #[test]
    fn arbor_shadow_detects_weak_md5_hash() {
        let line = "user:$1$salt$hash:18000:0:99999:7:::";
        let entry = parse_shadow_line(line).expect("shadow entry");
        assert_eq!(entry.hash_algorithm, "MD5");
        assert!(entry.is_weak_algorithm);
    }

    #[test]
    fn proc_net_tcp_decodes_ipv4_endpoints() {
        let line = "  0: 0100007F:1F90 6401A8C0:01BB 01 00000000:00000000 00:00000000 00000000";
        let entry = parse_proc_net_tcp_line(line).expect("tcp line");
        assert_eq!(entry.local_addr, "127.0.0.1");
        assert_eq!(entry.local_port, 8080);
        assert_eq!(entry.remote_addr, "192.168.1.100");
        assert_eq!(entry.remote_port, 443);
        assert_eq!(entry.state, "ESTABLISHED");
    }
}

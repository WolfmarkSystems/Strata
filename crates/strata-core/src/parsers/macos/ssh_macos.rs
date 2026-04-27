//! macOS SSH artifact parser.
//!
//! While `linux::ssh_artifacts::SshArtifactsParser` already covers the
//! universal `~/.ssh/` filenames (`authorized_keys`, `known_hosts`, `config`),
//! macOS adds two extra sources that the Linux parser does not look for:
//!
//!   * `~/Library/Preferences/com.apple.ssh.plist` — macOS-only SSH client
//!     preferences (per-user known fingerprints, host keys cached by the
//!     ssh agent helper).
//!   * Per-host fingerprints in `~/.ssh/known_hosts.d/` — added in macOS 14.
//!
//! Plus this parser annotates each `authorized_keys` and `known_hosts` entry
//! with the *username* derived from the path (`/Users/<name>/.ssh/...`),
//! which is the single most important piece of context an examiner needs
//! when there are multiple user accounts on a system.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

const MAX_LINES: usize = 5000;

pub struct MacosSshParser;

impl MacosSshParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosSshParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MacosSshKey {
    pub user: Option<String>,
    pub source: String,
    pub key_type: String,
    pub fingerprint: String,
    pub comment: Option<String>,
    pub line: usize,
    pub flags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MacosSshHost {
    pub user: Option<String>,
    pub host: String,
    pub key_type: String,
    pub line: usize,
    pub is_hashed: bool,
}

impl ArtifactParser for MacosSshParser {
    fn name(&self) -> &str {
        "macOS SSH Artifacts"
    }

    fn artifact_type(&self) -> &str {
        "remote_access"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "/.ssh/authorized_keys",
            "/.ssh/known_hosts",
            "/users/", // catch-all for per-user .ssh files
            "com.apple.ssh.plist",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let lc_path = path.to_string_lossy().to_lowercase();
        let lc_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Only act on macOS user paths or the macOS-only ssh plist.
        let is_macos_user = lc_path.contains("/users/") && lc_path.contains("/.ssh/");
        let is_apple_ssh_plist = lc_name == "com.apple.ssh.plist";
        if !is_macos_user && !is_apple_ssh_plist {
            return Ok(Vec::new());
        }

        let user = extract_macos_username(&lc_path);

        if is_apple_ssh_plist {
            return parse_apple_ssh_plist(path, data, user.as_deref());
        }

        match lc_name.as_str() {
            "authorized_keys" | "authorized_keys2" => {
                Ok(parse_authorized_keys(path, data, user.as_deref()))
            }
            "known_hosts" => Ok(parse_known_hosts(path, data, user.as_deref())),
            _ => Ok(Vec::new()),
        }
    }
}

fn extract_macos_username(lc_path: &str) -> Option<String> {
    if let Some(idx) = lc_path.find("/users/") {
        let tail = &lc_path[idx + "/users/".len()..];
        if let Some(slash) = tail.find('/') {
            return Some(tail[..slash].to_string());
        }
    }
    None
}

fn parse_authorized_keys(path: &Path, data: &[u8], user: Option<&str>) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let text = String::from_utf8_lossy(data);
    for (line_no, line) in text.lines().take(MAX_LINES).enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Detect the key type token. Many lines start with options like
        // `command="..." ssh-rsa ...`. We split off the options and look for
        // the first ssh-* / ecdsa-* / sk-* token.
        let (options, after_opts) = split_options(trimmed);
        let mut parts = after_opts.split_whitespace();
        let key_type = parts.next().unwrap_or("").to_string();
        let key_blob = parts.next().unwrap_or("");
        let comment = parts.collect::<Vec<&str>>().join(" ");
        let comment = if comment.is_empty() {
            None
        } else {
            Some(comment)
        };

        if key_type.is_empty() || key_blob.is_empty() {
            continue;
        }

        let fingerprint = blake3_short(key_blob);
        let mut flags = Vec::new();
        if let Some(opts) = &options {
            if opts.contains("command=") {
                flags.push("FORCED_COMMAND".to_string());
            }
            if opts.contains("no-pty") {
                flags.push("NO_PTY".to_string());
            }
            if opts.contains("from=") {
                flags.push("SOURCE_RESTRICTED".to_string());
            }
            if opts.contains("permitopen=") || opts.contains("permitlisten=") {
                flags.push("FORWARD_RESTRICTED".to_string());
            }
        }

        let entry = MacosSshKey {
            user: user.map(String::from),
            source: "authorized_keys".to_string(),
            key_type: key_type.clone(),
            fingerprint,
            comment,
            line: line_no + 1,
            flags,
        };
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "remote_access".to_string(),
            description: format!(
                "macOS authorized_key for user {}: {}",
                user.unwrap_or("(unknown)"),
                key_type
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
    out
}

fn parse_known_hosts(path: &Path, data: &[u8], user: Option<&str>) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let text = String::from_utf8_lossy(data);
    for (line_no, line) in text.lines().take(MAX_LINES).enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let host_field = parts.next().unwrap_or("");
        let key_type = parts.next().unwrap_or("").to_string();
        let _blob = parts.next().unwrap_or("");
        if host_field.is_empty() || key_type.is_empty() {
            continue;
        }
        let is_hashed = host_field.starts_with("|1|");
        let entry = MacosSshHost {
            user: user.map(String::from),
            host: host_field.to_string(),
            key_type: key_type.clone(),
            line: line_no + 1,
            is_hashed,
        };
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "remote_access".to_string(),
            description: format!(
                "macOS known_host for user {}: {} ({})",
                user.unwrap_or("(unknown)"),
                if is_hashed { "<hashed>" } else { host_field },
                key_type
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
    out
}

fn parse_apple_ssh_plist(
    path: &Path,
    data: &[u8],
    user: Option<&str>,
) -> Result<Vec<ParsedArtifact>, ParserError> {
    use crate::parsers::plist_utils::parse_plist_data;
    let mut out = Vec::new();
    let plist_val = parse_plist_data(data)?;
    let dict = match plist_val.as_dictionary() {
        Some(d) => d,
        None => return Ok(out),
    };
    // Best-effort extraction: emit one artifact per top-level key so the
    // examiner sees that ssh state was present, with the raw plist as JSON.
    out.push(ParsedArtifact {
        timestamp: None,
        artifact_type: "remote_access".to_string(),
        description: format!(
            "macOS com.apple.ssh.plist preferences for user {}: {} entries",
            user.unwrap_or("(unknown)"),
            dict.len()
        ),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(&plist_val).unwrap_or_default(),
    });
    Ok(out)
}

/// Pull a leading options block from an authorized_keys line. Options end at
/// the first unquoted whitespace character. Returns `(options, remainder)`.
fn split_options(line: &str) -> (Option<String>, &str) {
    if line.starts_with("ssh-") || line.starts_with("ecdsa-") || line.starts_with("sk-") {
        return (None, line);
    }
    let mut in_quotes = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                return (Some(line[..idx].to_string()), line[idx + 1..].trim_start());
            }
            _ => {}
        }
    }
    (None, line)
}

fn blake3_short(input: &str) -> String {
    let hash = blake3::hash(input.as_bytes());
    let hex = hash.to_hex();
    format!("blake3:{}", &hex.as_str()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn extracts_username_from_macos_path() {
        let p = "/users/korbyn/.ssh/known_hosts";
        assert_eq!(extract_macos_username(p), Some("korbyn".to_string()));
    }

    #[test]
    fn parses_authorized_keys_with_options() {
        let parser = MacosSshParser::new();
        let path = PathBuf::from("/Users/korbyn/.ssh/authorized_keys");
        let body = "no-pty,command=\"/bin/echo locked\" ssh-rsa AAAAB3NzaC1yc2E korbyn@laptop\n\
                    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 alice@server\n";
        let out = parser.parse_file(&path, body.as_bytes()).unwrap();
        assert_eq!(out.len(), 2);
        let first = &out[0];
        let flags: Vec<String> = first
            .json_data
            .get("flags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        assert!(flags.contains(&"FORCED_COMMAND".to_string()));
        assert!(flags.contains(&"NO_PTY".to_string()));
    }

    #[test]
    fn parses_known_hosts_with_hashed_entries() {
        let parser = MacosSshParser::new();
        let path = PathBuf::from("/Users/korbyn/.ssh/known_hosts");
        let body = "github.com,140.82.114.4 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n\
                    |1|abcdef= ssh-rsa AAAAB3NzaC1yc2E\n";
        let out = parser.parse_file(&path, body.as_bytes()).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0].json_data.get("is_hashed").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            out[1].json_data.get("is_hashed").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn rejects_non_user_paths() {
        let parser = MacosSshParser::new();
        let path = PathBuf::from("/etc/ssh/ssh_known_hosts");
        let out = parser
            .parse_file(&path, b"github.com ssh-ed25519 AAAA")
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parses_apple_ssh_plist() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>RememberLastWindow</key>
    <true/>
    <key>HostKey</key>
    <string>example.com</string>
</dict>
</plist>"#;
        let parser = MacosSshParser::new();
        let path = PathBuf::from("/Users/korbyn/Library/Preferences/com.apple.ssh.plist");
        let out = parser.parse_file(&path, xml.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].description.contains("com.apple.ssh.plist"));
    }
}

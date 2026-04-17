//! Gaming platform artifact detection (GAMING-1).
//!
//! ICAC-priority signal — predators commonly use gaming platforms to
//! contact children. We parse Steam VDF login + chat logs, Roblox
//! session logs, and detect Xbox Live local state files.
//!
//! MITRE: T1566 (phishing via gaming), T1534.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use std::fs;
use std::path::Path;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GamingArtifact {
    pub platform: String,
    pub username: Option<String>,
    pub user_id: Option<String>,
    pub message: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub contact: Option<String>,
    pub artifact_subtype: String,
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let mut out = Vec::new();
    // Steam loginusers.vdf.
    if name == "loginusers.vdf" {
        if let Ok(body) = fs::read_to_string(path) {
            for entry in parse_loginusers(&body) {
                out.push(steam_artifact(path, &entry, "login_record"));
            }
        }
        return out;
    }
    // Steam chat log.
    if name.starts_with("chat_log_") && name.ends_with(".txt") {
        if let Ok(body) = fs::read_to_string(path) {
            for msg in parse_chat_log(&body) {
                out.push(chat_artifact(path, "Steam", &msg));
            }
        }
        return out;
    }
    // Roblox logs.
    if (lower.contains("/roblox/logs/") || lower.contains("\\roblox\\logs\\")) && name.ends_with(".log")
    {
        if let Ok(body) = fs::read_to_string(path) {
            for msg in parse_chat_log(&body) {
                out.push(chat_artifact(path, "Roblox", &msg));
            }
        }
        return out;
    }
    // Xbox Live local state.
    if (lower.contains("microsoft.xboxapp_") || lower.contains("/xbox/localstate/"))
        && name.ends_with(".json")
    {
        let mut a = Artifact::new("Gaming Platform", &path.to_string_lossy());
        a.add_field("title", "Xbox Live local state JSON");
        a.add_field("file_type", "Gaming Platform");
        a.add_field("platform", "Xbox");
        a.add_field("artifact_subtype", "local_state");
        a.add_field("mitre", "T1566");
        a.add_field("forensic_value", "Medium");
        out.push(a);
    }
    out
}

fn steam_artifact(path: &Path, entry: &SteamLogin, subtype: &str) -> Artifact {
    let mut a = Artifact::new("Gaming Platform", &path.to_string_lossy());
    a.add_field(
        "title",
        &format!(
            "Steam login: {} ({})",
            entry.persona_name.as_deref().unwrap_or("?"),
            entry.account_name.as_deref().unwrap_or("?")
        ),
    );
    a.add_field(
        "detail",
        &format!(
            "Steam login: account={} | persona={} | last={} | remember_password={}",
            entry.account_name.as_deref().unwrap_or("-"),
            entry.persona_name.as_deref().unwrap_or("-"),
            entry
                .timestamp
                .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "-".to_string()),
            entry.remember_password
        ),
    );
    a.add_field("file_type", "Gaming Platform");
    a.add_field("platform", "Steam");
    a.add_field("artifact_subtype", subtype);
    if let Some(n) = &entry.persona_name {
        a.add_field("username", n);
    }
    if let Some(n) = &entry.account_name {
        a.add_field("user_id", n);
    }
    if let Some(t) = entry.timestamp {
        a.timestamp = Some(t.timestamp() as u64);
        a.add_field("timestamp", &t.format("%Y-%m-%d %H:%M:%S UTC").to_string());
    }
    a.add_field("mitre", "T1566");
    a.add_field("forensic_value", "Medium");
    a
}

fn chat_artifact(path: &Path, platform: &str, msg: &ChatLine) -> Artifact {
    let mut a = Artifact::new("Gaming Platform", &path.to_string_lossy());
    a.add_field(
        "title",
        &format!(
            "{} chat [{}]: {}",
            platform,
            msg.username.as_deref().unwrap_or("?"),
            msg.message.chars().take(80).collect::<String>()
        ),
    );
    a.add_field("file_type", "Gaming Platform");
    a.add_field("platform", platform);
    a.add_field("artifact_subtype", "chat_log");
    if let Some(u) = &msg.username {
        a.add_field("username", u);
    }
    a.add_field("message", &msg.message);
    if let Some(t) = msg.timestamp {
        a.timestamp = Some(t.timestamp() as u64);
        a.add_field("timestamp", &t.format("%Y-%m-%d %H:%M:%S UTC").to_string());
    }
    a.add_field("mitre", "T1566");
    a.add_field("forensic_value", "High");
    a.add_field("suspicious", "true");
    a
}

#[derive(Debug, Clone, Default)]
pub struct SteamLogin {
    pub account_name: Option<String>,
    pub persona_name: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub remember_password: bool,
}

pub fn parse_loginusers(body: &str) -> Vec<SteamLogin> {
    // Minimal VDF-ish scan: look for "AccountName", "PersonaName",
    // "Timestamp", "RememberPassword" within each block.
    let mut out: Vec<SteamLogin> = Vec::new();
    let mut current = SteamLogin::default();
    for line in body.lines() {
        let t = line.trim();
        if let Some((key, value)) = vdf_kv(t) {
            match key.as_str() {
                "AccountName" => current.account_name = Some(value),
                "PersonaName" => current.persona_name = Some(value),
                "Timestamp" => {
                    if let Ok(secs) = value.parse::<i64>() {
                        current.timestamp = DateTime::<Utc>::from_timestamp(secs, 0);
                    }
                }
                "RememberPassword" => {
                    current.remember_password = value == "1";
                }
                _ => {}
            }
        } else if t == "}" && (current.account_name.is_some() || current.persona_name.is_some()) {
            out.push(std::mem::take(&mut current));
        }
    }
    if current.account_name.is_some() || current.persona_name.is_some() {
        out.push(current);
    }
    out
}

fn vdf_kv(line: &str) -> Option<(String, String)> {
    // "Key"\t\t"Value"
    let rest = line.strip_prefix('"')?;
    let key_end = rest.find('"')?;
    let key = rest[..key_end].to_string();
    let after_key = &rest[key_end + 1..];
    let val_start = after_key.find('"')?;
    let val_rest = &after_key[val_start + 1..];
    let val_end = val_rest.find('"')?;
    Some((key, val_rest[..val_end].to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatLine {
    pub timestamp: Option<DateTime<Utc>>,
    pub username: Option<String>,
    pub message: String,
}

pub fn parse_chat_log(body: &str) -> Vec<ChatLine> {
    // `[YYYY-MM-DD HH:MM:SS] <PersonaName>: message`
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.trim_end_matches('\r');
        let Some(rest) = line.strip_prefix('[') else {
            continue;
        };
        let Some(close) = rest.find(']') else {
            continue;
        };
        let ts_str = &rest[..close];
        let after = rest[close + 1..].trim_start();
        let ts = NaiveDateTime::parse_from_str(ts_str.trim(), "%Y-%m-%d %H:%M:%S")
            .ok()
            .map(|ndt| Utc.from_utc_datetime(&ndt));
        if let Some(user_start) = after.strip_prefix('<') {
            if let Some(user_end) = user_start.find('>') {
                let user = user_start[..user_end].to_string();
                let msg = user_start[user_end + 1..].trim_start_matches(':').trim().to_string();
                out.push(ChatLine {
                    timestamp: ts,
                    username: Some(user),
                    message: msg,
                });
                continue;
            }
        }
        out.push(ChatLine {
            timestamp: ts,
            username: None,
            message: after.to_string(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_loginusers_extracts_account_and_persona() {
        let body = "\"users\"\n{\n\t\"76561198012345678\"\n\t{\n\t\t\"AccountName\"\t\t\"alice\"\n\t\t\"PersonaName\"\t\t\"AliceGamer\"\n\t\t\"Timestamp\"\t\t\"1717243200\"\n\t\t\"RememberPassword\"\t\t\"1\"\n\t}\n}\n";
        let entries = parse_loginusers(body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].account_name.as_deref(), Some("alice"));
        assert_eq!(entries[0].persona_name.as_deref(), Some("AliceGamer"));
        assert_eq!(entries[0].timestamp.map(|t| t.timestamp()), Some(1_717_243_200));
        assert!(entries[0].remember_password);
    }

    #[test]
    fn parse_chat_log_extracts_timestamped_message() {
        let body = "[2024-06-01 12:00:00] <Alice> hey there\n[2024-06-01 12:00:05] <Bob> hi\n";
        let msgs = parse_chat_log(body);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].username.as_deref(), Some("Alice"));
        assert_eq!(msgs[0].message, "hey there");
        assert_eq!(msgs[0].timestamp.map(|d| d.timestamp()), Some(1_717_243_200));
    }

    #[test]
    fn scan_emits_artifacts_for_loginusers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("loginusers.vdf");
        std::fs::write(
            &path,
            "\"users\"\n{\n\t\"76561198012345678\"\n\t{\n\t\t\"AccountName\"\t\t\"alice\"\n\t\t\"PersonaName\"\t\t\"AliceGamer\"\n\t\t\"Timestamp\"\t\t\"1717243200\"\n\t\t\"RememberPassword\"\t\t\"0\"\n\t}\n}\n",
        )
        .expect("write");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("platform").map(|s| s.as_str()) == Some("Steam")));
    }

    #[test]
    fn scan_emits_artifacts_for_roblox_log() {
        let dir = tempfile::tempdir().expect("tempdir");
        let logdir = dir.path().join("Roblox").join("logs");
        std::fs::create_dir_all(&logdir).expect("mkdirs");
        let path = logdir.join("session.log");
        std::fs::write(
            &path,
            "[2024-06-01 12:00:00] <Bobby> hello roblox\n",
        )
        .expect("write");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("platform").map(|s| s.as_str()) == Some("Roblox")));
    }

    #[test]
    fn scan_noop_on_unrelated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("random.txt");
        std::fs::write(&path, b"hi").expect("write");
        assert!(scan(&path).is_empty());
    }
}

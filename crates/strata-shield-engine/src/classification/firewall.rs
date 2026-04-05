use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use crate::errors::ForensicError;

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records};
use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};

#[derive(Debug, Clone, Default)]
pub struct FirewallRule {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub direction: RuleDirection,
    pub action: RuleAction,
    pub protocol: Option<String>,
    pub local_ports: Option<String>,
    pub remote_ports: Option<String>,
    pub local_addresses: Option<String>,
    pub remote_addresses: Option<String>,
    pub program: Option<String>,
    pub owner: Option<String>,
    pub profile: FirewallProfile,
}

#[derive(Debug, Clone, Default)]
pub enum RuleDirection {
    #[default]
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Default)]
pub enum RuleAction {
    #[default]
    Allow,
    Block,
}

#[derive(Debug, Clone, Default)]
pub struct FirewallProfile {
    pub domain: bool,
    pub private: bool,
    pub public: bool,
}

pub fn get_firewall_rules() -> Result<Vec<FirewallRule>, ForensicError> {
    Ok(get_firewall_rules_from_reg(&default_reg_path(
        "firewall.reg",
    )))
}

pub fn get_firewall_rules_from_reg(path: &Path) -> Vec<FirewallRule> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("firewallrules"))
    {
        for (value_name, raw) in &record.values {
            if let Some(text) = decode_reg_string(raw) {
                let parsed = parse_rule_blob(value_name, &text);
                out.push(parsed);
            }
        }
    }

    out
}

pub fn get_enabled_firewall_rules() -> Result<Vec<FirewallRule>, ForensicError> {
    Ok(get_firewall_rules()?
        .into_iter()
        .filter(|r| r.enabled)
        .collect())
}

pub fn get_blocked_firewall_rules() -> Result<Vec<FirewallRule>, ForensicError> {
    Ok(get_firewall_rules()?
        .into_iter()
        .filter(|r| matches!(r.action, RuleAction::Block))
        .collect())
}

pub fn get_firewall_log_path() -> String {
    if let Ok(path) = env::var("FORENSIC_FIREWALL_LOG") {
        return path;
    }
    r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log".to_string()
}

pub fn parse_firewall_log(log_path: &str) -> Result<Vec<FirewallLogEntry>, ForensicError> {
    Ok(parse_firewall_log_file(Path::new(log_path)))
}

pub fn parse_firewall_log_file(path: &Path) -> Vec<FirewallLogEntry> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 4) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 8 {
            continue;
        }
        let ts = timestamp_from_date_time(parts[0], parts[1]).unwrap_or(0);
        out.push(FirewallLogEntry {
            timestamp: ts,
            action: parts[2].to_string(),
            direction: "unknown".to_string(),
            protocol: parts[3].to_string(),
            src_ip: to_optional(parts.get(4).copied()),
            dst_ip: to_optional(parts.get(5).copied()),
            src_port: parts.get(6).and_then(|v| v.parse::<u16>().ok()),
            dst_port: parts.get(7).and_then(|v| v.parse::<u16>().ok()),
            program: parts
                .iter()
                .find(|token| token.starts_with("path="))
                .map(|token| token.trim_start_matches("path=").to_string()),
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct FirewallLogEntry {
    pub timestamp: u64,
    pub action: String,
    pub direction: String,
    pub protocol: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub program: Option<String>,
}

pub fn get_firewall_exceptions() -> Result<Vec<FirewallException>, ForensicError> {
    Ok(get_enabled_firewall_rules()?
        .into_iter()
        .filter_map(|rule| {
            if !matches!(rule.action, RuleAction::Allow) {
                return None;
            }
            let program_path = rule.program?;
            Some(FirewallException {
                program_path,
                allowed_connections: vec![
                    rule.protocol.unwrap_or_else(|| "any".to_string()),
                    rule.local_ports.unwrap_or_else(|| "any".to_string()),
                ],
                enabled: rule.enabled,
            })
        })
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct FirewallException {
    pub program_path: String,
    pub allowed_connections: Vec<String>,
    pub enabled: bool,
}

fn parse_rule_blob(value_name: &str, blob: &str) -> FirewallRule {
    let mut kv: HashMap<String, String> = HashMap::new();
    for part in blob.split('|') {
        if let Some((k, v)) = part.split_once('=') {
            kv.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let action = match kv.get("action").map(|v| v.to_ascii_lowercase()) {
        Some(v) if v == "block" => RuleAction::Block,
        _ => RuleAction::Allow,
    };
    let direction = match kv.get("dir").map(|v| v.to_ascii_lowercase()) {
        Some(v) if v == "out" || v == "outbound" => RuleDirection::Outbound,
        _ => RuleDirection::Inbound,
    };

    let profile_raw = kv
        .get("profile")
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_else(|| "all".to_string());
    let profile = FirewallProfile {
        domain: profile_raw.contains("domain") || profile_raw.contains("all"),
        private: profile_raw.contains("private") || profile_raw.contains("all"),
        public: profile_raw.contains("public") || profile_raw.contains("all"),
    };

    FirewallRule {
        name: kv
            .get("name")
            .cloned()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| value_name.to_string()),
        description: kv.get("desc").cloned().unwrap_or_default(),
        enabled: kv
            .get("active")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(true),
        direction,
        action,
        protocol: kv.get("protocol").cloned(),
        local_ports: kv.get("lport").cloned(),
        remote_ports: kv.get("rport").cloned(),
        local_addresses: kv.get("lip").cloned(),
        remote_addresses: kv.get("rip").cloned(),
        program: kv.get("app").cloned(),
        owner: kv.get("owner").cloned(),
        profile,
    }
}

fn to_optional(value: Option<&str>) -> Option<String> {
    let v = value?.trim();
    if v.is_empty() || v == "-" {
        None
    } else {
        Some(v.to_string())
    }
}

fn timestamp_from_date_time(date: &str, time: &str) -> Option<u64> {
    let d: Vec<&str> = date.split('-').collect();
    let t: Vec<&str> = time.split(':').collect();
    if d.len() != 3 || t.len() < 2 {
        return None;
    }
    let year = d[0].parse::<i32>().ok()?;
    let month = d[1].parse::<u32>().ok()?;
    let day = d[2].parse::<u32>().ok()?;
    let hour = t[0].parse::<u32>().ok()?;
    let minute = t[1].parse::<u32>().ok()?;
    let second = t.get(2).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    unix_from_ymd_hms(year, month, day, hour, minute, second)
}

fn unix_from_ymd_hms(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<u64> {
    if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let y = year - ((month <= 2) as i32);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i32;
    let d = day as i32;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days as i64 * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64;
    if secs < 0 {
        None
    } else {
        Some(secs as u64)
    }
}

fn _firewall_rules_reg_path() -> PathBuf {
    default_reg_path("firewall.reg")
}

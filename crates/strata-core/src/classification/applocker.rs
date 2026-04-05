use std::env;
use std::path::{Path, PathBuf};

use crate::errors::ForensicError;

use super::reg_export::{decode_reg_string, default_reg_path, key_leaf, load_reg_records};
use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};

#[derive(Debug, Clone, Default)]
pub struct AppLockerRule {
    pub name: String,
    pub rule_type: RuleType,
    pub action: String,
    pub path: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub enum RuleType {
    #[default]
    Exe,
    Script,
    Dll,
}

pub fn get_applocker_rules() -> Result<Vec<AppLockerRule>, ForensicError> {
    Ok(get_applocker_rules_from_reg(&default_reg_path(
        "applocker.reg",
    )))
}

pub fn get_applocker_rules_from_reg(path: &Path) -> Vec<AppLockerRule> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("applocker") || p.contains("srpv2")
    }) {
        let name = record
            .values
            .get("Name")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| key_leaf(&record.path));
        let action = record
            .values
            .get("Action")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| "Unknown".to_string());
        let path = record
            .values
            .get("Path")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| {
                record
                    .values
                    .get("FilePath")
                    .and_then(|v| decode_reg_string(v))
            });
        let hash = record.values.get("Hash").and_then(|v| decode_reg_string(v));
        let rule_type = infer_rule_type(record);

        out.push(AppLockerRule {
            name,
            rule_type,
            action,
            path,
            hash,
        });
    }

    out
}

pub fn get_applocker_log() -> Result<Vec<AppLockerLogEntry>, ForensicError> {
    let path = applocker_log_path();
    Ok(parse_applocker_log(&path))
}

pub fn parse_applocker_log(path: &Path) -> Vec<AppLockerLogEntry> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 2) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(parsed) = parse_applocker_log_line(trimmed) {
            out.push(parsed);
        }
    }
    out
}

fn parse_applocker_log_line(line: &str) -> Option<AppLockerLogEntry> {
    let parts: Vec<&str> = if line.contains('|') {
        line.split('|').collect()
    } else {
        line.split(',').collect()
    };
    if parts.len() < 4 {
        return None;
    }

    Some(AppLockerLogEntry {
        timestamp: parts[0].trim().parse::<u64>().unwrap_or(0),
        rule_name: parts[1].trim().to_string(),
        action: parts[2].trim().to_string(),
        file_path: parts[3].trim().to_string(),
    })
}

fn infer_rule_type(record: &super::reg_export::RegKeyRecord) -> RuleType {
    let mut signal = record.path.to_ascii_lowercase();
    if let Some(v) = record
        .values
        .get("RuleType")
        .and_then(|v| decode_reg_string(v))
    {
        signal.push(' ');
        signal.push_str(&v.to_ascii_lowercase());
    }
    if let Some(v) = record
        .values
        .get("CollectionType")
        .and_then(|v| decode_reg_string(v))
    {
        signal.push(' ');
        signal.push_str(&v.to_ascii_lowercase());
    }

    if signal.contains("script") {
        RuleType::Script
    } else if signal.contains("dll") {
        RuleType::Dll
    } else {
        RuleType::Exe
    }
}

fn applocker_log_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_APPLOCKER_LOG") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("logs")
        .join("applocker.log")
}

#[derive(Debug, Clone, Default)]
pub struct AppLockerLogEntry {
    pub timestamp: u64,
    pub rule_name: String,
    pub action: String,
    pub file_path: String,
}

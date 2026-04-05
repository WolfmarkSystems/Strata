use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use crate::errors::ForensicError;

#[derive(Debug, Clone, Default)]
pub struct CmdHistory {
    pub command: String,
    pub execution_time: u64,
    pub count: u32,
}

pub fn get_cmd_history() -> Result<Vec<CmdHistory>, ForensicError> {
    Ok(parse_cmd_history_file(&cmd_history_path()))
}

pub fn parse_cmd_history_file(path: &Path) -> Vec<CmdHistory> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut counts: BTreeMap<String, (u32, u64)> = BTreeMap::new();
    for (idx, line) in content.lines().enumerate() {
        let command = line.trim();
        if command.is_empty() || command.starts_with('#') {
            continue;
        }
        let entry = counts.entry(command.to_string()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = idx as u64;
    }

    counts
        .into_iter()
        .map(|(command, (count, execution_time))| CmdHistory {
            command,
            execution_time,
            count,
        })
        .collect()
}

pub fn get_autoexec_ntconfig() -> Result<BootConfig, ForensicError> {
    Ok(BootConfig {
        autoexec: read_text_if_exists(&autoexec_path()),
        ntconfig: read_text_if_exists(&ntconfig_path()),
    })
}

#[derive(Debug, Clone, Default)]
pub struct BootConfig {
    pub autoexec: String,
    pub ntconfig: String,
}

pub fn get_cmd_aliases() -> Result<Vec<CmdAlias>, ForensicError> {
    Ok(parse_cmd_aliases_file(&cmd_aliases_path()))
}

pub fn parse_cmd_aliases_file(path: &Path) -> Vec<CmdAlias> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((alias, command)) = trimmed.split_once('=') {
            out.push(CmdAlias {
                alias: alias.trim().to_string(),
                command: command.trim().to_string(),
            });
        } else if let Some((alias, command)) = trimmed.split_once('|') {
            out.push(CmdAlias {
                alias: alias.trim().to_string(),
                command: command.trim().to_string(),
            });
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct CmdAlias {
    pub alias: String,
    pub command: String,
}

pub fn get_batch_scripts() -> Result<Vec<BatchScript>, ForensicError> {
    Ok(parse_batch_scripts_log(&batch_scripts_path()))
}

pub fn parse_batch_scripts_log(path: &Path) -> Vec<BatchScript> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = if trimmed.contains('|') {
            trimmed.split('|').collect()
        } else {
            trimmed.split(',').collect()
        };
        if parts.is_empty() {
            continue;
        }
        out.push(BatchScript {
            path: parts[0].trim().to_string(),
            last_run: parts.get(1).and_then(|v| v.trim().parse::<u64>().ok()),
            run_count: parts
                .get(2)
                .and_then(|v| v.trim().parse::<u32>().ok())
                .unwrap_or(1),
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct BatchScript {
    pub path: String,
    pub last_run: Option<u64>,
    pub run_count: u32,
}

fn read_text_if_exists(path: &Path) -> String {
    read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES).unwrap_or_default()
}

fn cmd_history_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_CMD_HISTORY") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("console")
        .join("cmd_history.txt")
}

fn cmd_aliases_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_CMD_ALIASES") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("console")
        .join("cmd_aliases.txt")
}

fn batch_scripts_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_BATCH_SCRIPTS") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("console")
        .join("batch_scripts.log")
}

fn autoexec_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_AUTOEXEC_NT") {
        return PathBuf::from(path);
    }
    PathBuf::from(r"C:\Windows\System32\autoexec.nt")
}

fn ntconfig_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_CONFIG_NT") {
        return PathBuf::from(path);
    }
    PathBuf::from(r"C:\Windows\System32\config.nt")
}

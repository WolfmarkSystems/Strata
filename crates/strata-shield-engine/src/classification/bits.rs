use std::env;
use std::path::{Path, PathBuf};

use crate::errors::ForensicError;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u64,
};
use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};

#[derive(Debug, Clone, Default)]
pub struct BITSJob {
    pub job_id: String,
    pub display_name: String,
    pub state: String,
    pub priority: String,
}

pub fn get_bits_jobs() -> Result<Vec<BITSJob>, ForensicError> {
    Ok(get_bits_jobs_from_reg(&default_reg_path("bits.reg")))
}

pub fn get_bits_jobs_from_reg(path: &Path) -> Vec<BITSJob> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("bits"))
    {
        out.push(BITSJob {
            job_id: key_leaf(&record.path),
            display_name: record
                .values
                .get("DisplayName")
                .and_then(|v| decode_reg_string(v))
                .or_else(|| {
                    record
                        .values
                        .get("Description")
                        .and_then(|v| decode_reg_string(v))
                })
                .unwrap_or_default(),
            state: record
                .values
                .get("State")
                .and_then(|v| decode_reg_string(v))
                .or_else(|| {
                    record
                        .values
                        .get("JobState")
                        .and_then(|v| decode_reg_string(v))
                })
                .unwrap_or_else(|| "Unknown".to_string()),
            priority: record
                .values
                .get("Priority")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| "Normal".to_string()),
        });
    }

    out
}

pub fn get_bits_transfer_history() -> Result<Vec<BITSTransfer>, ForensicError> {
    let mut out = get_bits_transfer_history_from_reg(&default_reg_path("bits.reg"));
    out.extend(parse_bits_transfer_log(&bits_history_path()));
    Ok(out)
}

pub fn get_bits_transfer_history_from_reg(path: &Path) -> Vec<BITSTransfer> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("bits"))
    {
        let url = record
            .values
            .get("RemoteName")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| record.values.get("Url").and_then(|v| decode_reg_string(v)))
            .unwrap_or_default();
        let local_path = record
            .values
            .get("LocalName")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| {
                record
                    .values
                    .get("LocalPath")
                    .and_then(|v| decode_reg_string(v))
            })
            .unwrap_or_default();

        if url.is_empty() && local_path.is_empty() {
            continue;
        }

        out.push(BITSTransfer {
            job_name: record
                .values
                .get("DisplayName")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| key_leaf(&record.path)),
            url,
            local_path,
            start_time: record
                .values
                .get("CreationTime")
                .and_then(|v| parse_reg_u64(v))
                .unwrap_or(0),
            end_time: record
                .values
                .get("ModificationTime")
                .and_then(|v| parse_reg_u64(v)),
        });
    }

    out
}

pub fn parse_bits_transfer_log(path: &Path) -> Vec<BITSTransfer> {
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
        let parts: Vec<&str> = if trimmed.contains('|') {
            trimmed.split('|').collect()
        } else {
            trimmed.split(',').collect()
        };
        if parts.len() < 4 {
            continue;
        }
        out.push(BITSTransfer {
            job_name: parts[0].trim().to_string(),
            url: parts[1].trim().to_string(),
            local_path: parts[2].trim().to_string(),
            start_time: parts[3].trim().parse::<u64>().unwrap_or(0),
            end_time: parts.get(4).and_then(|v| v.trim().parse::<u64>().ok()),
        });
    }

    out
}

fn bits_history_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_BITS_HISTORY") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("network")
        .join("bits_transfers.log")
}

#[derive(Debug, Clone, Default)]
pub struct BITSTransfer {
    pub job_name: String,
    pub url: String,
    pub local_path: String,
    pub start_time: u64,
    pub end_time: Option<u64>,
}

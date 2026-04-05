use crate::errors::ForensicError;
use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u64,
    parse_yyyymmdd_to_unix, unix_to_utc_rfc3339,
};
use super::reguninstall;

#[derive(Debug, Clone, Default)]
pub struct WindowsUpdate {
    pub kb_number: String,
    pub title: String,
    pub description: String,
    pub installed_date: Option<u64>,
    pub installed_date_utc: Option<String>,
    pub install_result: InstallResult,
    pub reboot_required: bool,
    pub is_hidden: bool,
}

#[derive(Debug, Clone, Default)]
pub enum InstallResult {
    #[default]
    Unknown,
    Succeeded,
    Failed,
    Pending,
    Downloaded,
}

pub fn get_installed_updates() -> Result<Vec<WindowsUpdate>, ForensicError> {
    let mut out = Vec::new();
    for row in reguninstall::get_windows_update() {
        out.push(WindowsUpdate {
            kb_number: row.hotfix_id.clone(),
            title: row.hotfix_id,
            description: "Installed update".to_string(),
            installed_date: row.installed_on,
            installed_date_utc: row.installed_on_utc,
            install_result: InstallResult::Succeeded,
            reboot_required: false,
            is_hidden: false,
        });
    }

    // Also include any additional update records from explicit registry exports.
    out.extend(read_updates_from_reg(&default_reg_path("updates.reg")));
    Ok(out)
}

pub fn get_pending_updates() -> Result<Vec<WindowsUpdate>, ForensicError> {
    Ok(read_updates_from_reg(&default_reg_path("updates.reg"))
        .into_iter()
        .filter(|u| matches!(u.install_result, InstallResult::Pending))
        .collect())
}

pub fn get_update_history() -> Result<Vec<WindowsUpdate>, ForensicError> {
    get_installed_updates()
}

pub fn get_failed_updates() -> Result<Vec<WindowsUpdate>, ForensicError> {
    Ok(read_updates_from_reg(&default_reg_path("updates.reg"))
        .into_iter()
        .filter(|u| matches!(u.install_result, InstallResult::Failed))
        .collect())
}

pub fn get_windows_servicing_queue() -> Result<Vec<ServicingQueueItem>, ForensicError> {
    let updates = read_updates_from_reg(&default_reg_path("updates.reg"));
    Ok(updates
        .into_iter()
        .map(|u| ServicingQueueItem {
            name: if u.kb_number.is_empty() {
                u.title
            } else {
                u.kb_number
            },
            state: match u.install_result {
                InstallResult::Succeeded => "succeeded",
                InstallResult::Failed => "failed",
                InstallResult::Pending => "pending",
                InstallResult::Downloaded => "downloaded",
                InstallResult::Unknown => "unknown",
            }
            .to_string(),
            priority: if u.reboot_required { 10 } else { 5 },
        })
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct ServicingQueueItem {
    pub name: String,
    pub state: String,
    pub priority: u32,
}

pub fn get_update_source_info() -> Result<UpdateSourceInfo, ForensicError> {
    let records = load_reg_records(&default_reg_path("updates.reg"));
    if let Some(record) = records
        .iter()
        .find(|r| r.path.to_ascii_lowercase().contains("\\windowsupdate\\"))
    {
        return Ok(UpdateSourceInfo {
            source_type: if record
                .values
                .get("WUServer")
                .and_then(|v| decode_reg_string(v))
                .is_some()
            {
                "WSUS".to_string()
            } else {
                "WindowsUpdate".to_string()
            },
            server_url: record
                .values
                .get("WUServer")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            last_sync: record
                .values
                .get("LastSuccessTime")
                .and_then(|v| parse_timestamp_raw(v)),
            last_sync_utc: record
                .values
                .get("LastSuccessTime")
                .and_then(|v| parse_timestamp_raw(v))
                .and_then(unix_to_utc_rfc3339),
        });
    }

    Ok(UpdateSourceInfo {
        source_type: "WSUS".to_string(),
        server_url: "".to_string(),
        last_sync: None,
        last_sync_utc: None,
    })
}

#[derive(Debug, Clone, Default)]
pub struct UpdateSourceInfo {
    pub source_type: String,
    pub server_url: String,
    pub last_sync: Option<u64>,
    pub last_sync_utc: Option<String>,
}

pub fn check_for_pending_reboot() -> bool {
    let records = load_reg_records(&default_reg_path("updates.reg"));
    records
        .iter()
        .any(|r| r.path.to_ascii_lowercase().contains("rebootrequired"))
}

fn read_updates_from_reg(path: &Path) -> Vec<WindowsUpdate> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("windowsupdate") || p.contains("component based servicing")
    }) {
        let title = record
            .values
            .get("Title")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| key_leaf(&record.path));
        let kb_number = find_kb(&title).unwrap_or_default();
        let result = record
            .values
            .get("Result")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_default()
            .to_ascii_lowercase();
        let install_result = if result.contains("success") {
            InstallResult::Succeeded
        } else if result.contains("fail") {
            InstallResult::Failed
        } else if result.contains("pending") {
            InstallResult::Pending
        } else if result.contains("download") {
            InstallResult::Downloaded
        } else {
            InstallResult::Unknown
        };

        let installed_date = record
            .values
            .get("InstalledOn")
            .and_then(|v| parse_timestamp_raw(v));

        out.push(WindowsUpdate {
            kb_number,
            title,
            description: record
                .values
                .get("Description")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            installed_date,
            installed_date_utc: installed_date.and_then(unix_to_utc_rfc3339),
            install_result,
            reboot_required: record.path.to_ascii_lowercase().contains("rebootrequired"),
            is_hidden: record
                .values
                .get("IsHidden")
                .and_then(|v| decode_reg_string(v))
                .map(|v| v == "1")
                .unwrap_or(false),
        });
    }
    out
}

fn parse_timestamp_raw(raw: &str) -> Option<u64> {
    if let Some(unix) = parse_reg_u64(raw) {
        if unix >= 946_684_800 {
            return Some(unix);
        }
        if let Some(from_ymd) = parse_yyyymmdd_to_unix(&unix.to_string()) {
            return Some(from_ymd);
        }
    }
    decode_reg_string(raw)
        .and_then(|v| parse_yyyymmdd_to_unix(&v).or_else(|| v.parse::<u64>().ok()))
        .filter(|unix| *unix >= 946_684_800)
}

fn find_kb(title: &str) -> Option<String> {
    let upper = title.to_ascii_uppercase();
    let idx = upper.find("KB")?;
    let s = &upper[idx..];
    let mut kb = String::from("KB");
    for ch in s[2..].chars() {
        if ch.is_ascii_digit() {
            kb.push(ch);
        } else {
            break;
        }
    }
    if kb.len() > 2 {
        Some(kb)
    } else {
        None
    }
}

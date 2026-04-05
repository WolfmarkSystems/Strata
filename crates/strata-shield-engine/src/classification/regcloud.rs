use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records, parse_reg_u32};

pub fn get_cloud_storage() -> Vec<CloudStorage> {
    get_cloud_storage_from_reg(&default_reg_path("cloud.reg"))
}

pub fn get_cloud_storage_from_reg(path: &Path) -> Vec<CloudStorage> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in &records {
        let p = record.path.to_ascii_lowercase();
        if p.contains("onedrive") {
            out.push(CloudStorage {
                provider: "OneDrive".to_string(),
                account: record
                    .values
                    .get("UserEmail")
                    .and_then(|v| decode_reg_string(v))
                    .unwrap_or_default(),
                sync_folder: record
                    .values
                    .get("UserFolder")
                    .and_then(|v| decode_reg_string(v))
                    .unwrap_or_default(),
            });
        } else if p.contains("dropbox") {
            out.push(CloudStorage {
                provider: "Dropbox".to_string(),
                account: record
                    .values
                    .get("UserEmail")
                    .and_then(|v| decode_reg_string(v))
                    .unwrap_or_default(),
                sync_folder: record
                    .values
                    .get("PersonalPath")
                    .and_then(|v| decode_reg_string(v))
                    .unwrap_or_default(),
            });
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct CloudStorage {
    pub provider: String,
    pub account: String,
    pub sync_folder: String,
}

pub fn get_onedrive_state() -> OneDriveState {
    get_onedrive_state_from_reg(&default_reg_path("cloud.reg"))
}

pub fn get_onedrive_state_from_reg(path: &Path) -> OneDriveState {
    let records = load_reg_records(path);
    if let Some(record) = records
        .iter()
        .find(|r| r.path.to_ascii_lowercase().contains("onedrive"))
    {
        OneDriveState {
            user: record
                .values
                .get("UserEmail")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            sync_enabled: record
                .values
                .get("DisableFileSyncNGSC")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                == 0,
        }
    } else {
        OneDriveState::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct OneDriveState {
    pub user: String,
    pub sync_enabled: bool,
}

pub fn get_dropbox_state() -> DropboxState {
    get_dropbox_state_from_reg(&default_reg_path("cloud.reg"))
}

pub fn get_dropbox_state_from_reg(path: &Path) -> DropboxState {
    let records = load_reg_records(path);
    if let Some(record) = records
        .iter()
        .find(|r| r.path.to_ascii_lowercase().contains("dropbox"))
    {
        DropboxState {
            user: record
                .values
                .get("UserEmail")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            host_id: record
                .values
                .get("HostId")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
        }
    } else {
        DropboxState::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct DropboxState {
    pub user: String,
    pub host_id: String,
}

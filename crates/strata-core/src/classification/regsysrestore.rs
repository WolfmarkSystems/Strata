use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32, parse_reg_u64,
};

pub fn get_system_restore_config() -> RestoreConfig {
    get_system_restore_config_from_reg(&default_reg_path("sysrestore.reg"))
}

pub fn get_system_restore_config_from_reg(path: &Path) -> RestoreConfig {
    let records = load_reg_records(path);
    if let Some(record) = records
        .iter()
        .find(|r| r.path.to_ascii_lowercase().contains("\\systemrestore"))
    {
        RestoreConfig {
            enabled: record
                .values
                .get("DisableSR")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                == 0,
            max_size: record
                .values
                .get("DiskPercent")
                .and_then(|v| parse_reg_u64(v))
                .unwrap_or(0),
        }
    } else {
        RestoreConfig::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RestoreConfig {
    pub enabled: bool,
    pub max_size: u64,
}

pub fn get_restore_points_all() -> Vec<RestorePointFull> {
    get_restore_points_all_from_reg(&default_reg_path("sysrestore.reg"))
}

pub fn get_restore_points_all_from_reg(path: &Path) -> Vec<RestorePointFull> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\restorepoints\\"))
    {
        out.push(RestorePointFull {
            id: key_leaf(&record.path).parse::<u32>().unwrap_or(0),
            description: record
                .values
                .get("Description")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            timestamp: record
                .values
                .get("CreationTime")
                .and_then(|v| parse_reg_u64(v))
                .unwrap_or(0),
            type_name: record
                .values
                .get("EventType")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct RestorePointFull {
    pub id: u32,
    pub description: String,
    pub timestamp: u64,
    pub type_name: String,
}

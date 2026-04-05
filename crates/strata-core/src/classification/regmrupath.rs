use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32,
};

pub fn get_mru_paths() -> Vec<MruPath> {
    get_mru_paths_from_reg(&default_reg_path("mrupath.reg"))
}

pub fn get_mru_paths_from_reg(path: &Path) -> Vec<MruPath> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("\\recentdocs") || p.contains("\\opensavemru")
    }) {
        for (name, raw) in &record.values {
            if let Some(value) = decode_reg_string(raw) {
                out.push(MruPath {
                    key: name.clone(),
                    value,
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct MruPath {
    pub key: String,
    pub value: String,
}

pub fn get_dock_settings() -> DockSettings {
    get_dock_settings_from_reg(&default_reg_path("mrupath.reg"))
}

pub fn get_dock_settings_from_reg(path: &Path) -> DockSettings {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\explorer\\stuckrects3")
    }) {
        DockSettings {
            autohide: record
                .values
                .get("Settings")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            position: record
                .values
                .get("TaskbarAl")
                .and_then(|v| parse_reg_u32(v))
                .map(|v| if v == 1 { "center" } else { "left" }.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        }
    } else {
        DockSettings::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct DockSettings {
    pub autohide: bool,
    pub position: String,
}

pub fn get_notification_settings() -> Vec<NotificationSetting> {
    get_notification_settings_from_reg(&default_reg_path("mrupath.reg"))
}

pub fn get_notification_settings_from_reg(path: &Path) -> Vec<NotificationSetting> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\notifications\\settings\\")
    }) {
        let app = key_leaf(&record.path);
        let enabled = record
            .values
            .get("Enabled")
            .and_then(|v| parse_reg_u32(v))
            .unwrap_or(1)
            != 0;
        out.push(NotificationSetting { app, enabled });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct NotificationSetting {
    pub app: String,
    pub enabled: bool,
}

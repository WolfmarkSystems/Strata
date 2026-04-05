use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_hex_bytes,
};

pub fn get_app_assist() -> Vec<AppAssistEntry> {
    get_app_assist_from_reg(&default_reg_path("app.reg"))
}

pub fn get_app_assist_from_reg(path: &Path) -> Vec<AppAssistEntry> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("appcompatflags"))
    {
        for (name, raw) in &record.values {
            if let Some(bytes) = parse_hex_bytes(raw) {
                out.push(AppAssistEntry {
                    app_name: name.clone(),
                    value: bytes,
                });
            }
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct AppAssistEntry {
    pub app_name: String,
    pub value: Vec<u8>,
}

pub fn get_app_compat_flags() -> Vec<CompatFlag> {
    get_app_compat_flags_from_reg(&default_reg_path("app.reg"))
}

pub fn get_app_compat_flags_from_reg(path: &Path) -> Vec<CompatFlag> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("appcompatflags\\layers")
    }) {
        for (program, raw) in &record.values {
            if let Some(flags) = decode_reg_string(raw) {
                out.push(CompatFlag {
                    program: program.clone(),
                    flags,
                });
            }
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct CompatFlag {
    pub program: String,
    pub flags: String,
}

pub fn get_app_paths() -> Vec<AppPath> {
    get_app_paths_from_reg(&default_reg_path("app.reg"))
}

pub fn get_app_paths_from_reg(path: &Path) -> Vec<AppPath> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\app paths\\"))
    {
        let app_name = key_leaf(&record.path);
        let path_value = record
            .values
            .get("@")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_default();
        if !path_value.is_empty() {
            out.push(AppPath {
                name: app_name,
                path: path_value,
            });
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct AppPath {
    pub name: String,
    pub path: String,
}

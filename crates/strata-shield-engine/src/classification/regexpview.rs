use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32,
};

pub fn get_windows_explorer() -> ExplorerSettings {
    get_windows_explorer_from_reg(&default_reg_path("explorer.reg"))
}

pub fn get_windows_explorer_from_reg(path: &Path) -> ExplorerSettings {
    let records = load_reg_records(path);
    if let Some(record) = records
        .iter()
        .find(|r| r.path.to_ascii_lowercase().contains("\\explorer\\advanced"))
    {
        ExplorerSettings {
            show_hidden: record
                .values
                .get("Hidden")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            show_extensions: record
                .values
                .get("HideFileExt")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(1)
                == 0,
            show_protected: record
                .values
                .get("ShowSuperHidden")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
        }
    } else {
        ExplorerSettings::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExplorerSettings {
    pub show_hidden: bool,
    pub show_extensions: bool,
    pub show_protected: bool,
}

pub fn get_recent_files() -> Vec<RecentFile> {
    get_recent_files_from_reg(&default_reg_path("explorer.reg"))
}

pub fn get_recent_files_from_reg(path: &Path) -> Vec<RecentFile> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\recentdocs"))
    {
        for raw in record.values.values() {
            if let Some(path_value) = decode_reg_string(raw) {
                out.push(RecentFile {
                    name: key_leaf(&path_value),
                    path: path_value,
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct RecentFile {
    pub name: String,
    pub path: String,
}

pub fn get_folder_views() -> Vec<FolderView> {
    get_folder_views_from_reg(&default_reg_path("explorer.reg"))
}

pub fn get_folder_views_from_reg(path: &Path) -> Vec<FolderView> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\bagmru"))
    {
        out.push(FolderView {
            path: record.path.clone(),
            view_mode: record
                .values
                .get("Mode")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| "Unknown".to_string()),
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct FolderView {
    pub path: String,
    pub view_mode: String,
}

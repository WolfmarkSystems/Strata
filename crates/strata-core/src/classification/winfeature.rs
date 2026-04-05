use std::path::Path;

use super::reg_export::{default_reg_path, key_leaf, load_reg_records, parse_reg_u32};

pub fn get_installed_features() -> Vec<WindowsFeature> {
    get_installed_features_from_reg(&default_reg_path("features.reg"))
}

pub fn get_installed_features_from_reg(path: &Path) -> Vec<WindowsFeature> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("\\component based servicing\\packages\\") || p.contains("\\optionalfeatures\\")
    }) {
        let state = record
            .values
            .get("CurrentState")
            .and_then(|v| parse_reg_u32(v))
            .unwrap_or(0);
        // CBS CurrentState: 0x70 often indicates installed.
        let enabled = matches!(state, 0x70 | 0x20);
        out.push(WindowsFeature {
            name: key_leaf(&record.path),
            enabled,
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct WindowsFeature {
    pub name: String,
    pub enabled: bool,
}

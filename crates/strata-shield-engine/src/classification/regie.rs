use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32,
};

pub fn get_ie_settings() -> IeSettings {
    get_ie_settings_from_reg(&default_reg_path("ie.reg"))
}

pub fn get_ie_settings_from_reg(path: &Path) -> IeSettings {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\internet explorer\\main")
    }) {
        IeSettings {
            homepage: record
                .values
                .get("Start Page")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            search_provider: record
                .values
                .get("Search Page")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
        }
    } else {
        IeSettings::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct IeSettings {
    pub homepage: String,
    pub search_provider: String,
}

pub fn get_ie_zones() -> Vec<IeZone> {
    get_ie_zones_from_reg(&default_reg_path("ie.reg"))
}

pub fn get_ie_zones_from_reg(path: &Path) -> Vec<IeZone> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\internet settings\\zones\\")
    }) {
        let zone_id = key_leaf(&record.path).parse::<u32>().unwrap_or(0);
        out.push(IeZone {
            zone_id,
            name: record
                .values
                .get("DisplayName")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| format!("Zone {zone_id}")),
            custom_level: record
                .values
                .get("CurrentLevel")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0),
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct IeZone {
    pub zone_id: u32,
    pub name: String,
    pub custom_level: u32,
}

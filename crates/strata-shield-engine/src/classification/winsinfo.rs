use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records};

pub fn get_wins_config() -> WinsConfig {
    get_wins_config_from_reg(&default_reg_path("wins.reg"))
}

pub fn get_wins_config_from_reg(path: &Path) -> WinsConfig {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("\\services\\netbt\\parameters") || p.contains("\\wins")
    }) {
        WinsConfig {
            primary_server: record
                .values
                .get("NameServer")
                .and_then(|v| decode_reg_string(v))
                .or_else(|| {
                    record
                        .values
                        .get("PrimaryWINS")
                        .and_then(|v| decode_reg_string(v))
                })
                .unwrap_or_default(),
        }
    } else {
        WinsConfig::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct WinsConfig {
    pub primary_server: String,
}

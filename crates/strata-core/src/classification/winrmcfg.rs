use std::path::Path;

use super::reg_export::{default_reg_path, load_reg_records, parse_reg_u32};

pub fn get_winrm_config() -> WinrmConfig {
    get_winrm_config_from_reg(&default_reg_path("winrm.reg"))
}

pub fn get_winrm_config_from_reg(path: &Path) -> WinrmConfig {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\windows\\winrm\\service")
    }) {
        let port = record
            .values
            .get("HttpPort")
            .and_then(|v| parse_reg_u32(v))
            .unwrap_or(5985);
        WinrmConfig {
            enabled: record
                .values
                .get("AllowAutoConfig")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            port: u16::try_from(port).unwrap_or(5985),
        }
    } else {
        WinrmConfig::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct WinrmConfig {
    pub enabled: bool,
    pub port: u16,
}

use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32,
};

pub fn get_windows_defender_config() -> DefenderConfig {
    get_windows_defender_config_from_reg(&default_reg_path("defender.reg"))
}

pub fn get_windows_defender_config_from_reg(path: &Path) -> DefenderConfig {
    let records = load_reg_records(path);
    if let Some(record) = records
        .iter()
        .find(|r| r.path.to_ascii_lowercase().contains("\\windows defender\\"))
    {
        DefenderConfig {
            realtime_protection: record
                .values
                .get("DisableRealtimeMonitoring")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                == 0,
            behavior_monitoring: record
                .values
                .get("DisableBehaviorMonitoring")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                == 0,
            script_scanning: record
                .values
                .get("DisableScriptScanning")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                == 0,
        }
    } else {
        DefenderConfig::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct DefenderConfig {
    pub realtime_protection: bool,
    pub behavior_monitoring: bool,
    pub script_scanning: bool,
}

pub fn get_defender_exclusions() -> Vec<String> {
    get_defender_exclusions_from_reg(&default_reg_path("defender.reg"))
}

pub fn get_defender_exclusions_from_reg(path: &Path) -> Vec<String> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("windows defender\\exclusions")
    }) {
        for (name, raw) in &record.values {
            if let Some(value) = decode_reg_string(raw) {
                if !value.is_empty() {
                    out.push(value);
                } else {
                    out.push(name.clone());
                }
            } else {
                out.push(name.clone());
            }
        }
    }
    out
}

pub fn get_windows_firewall_config() -> FirewallConfig {
    get_windows_firewall_config_from_reg(&default_reg_path("defender.reg"))
}

pub fn get_windows_firewall_config_from_reg(path: &Path) -> FirewallConfig {
    let records = load_reg_records(path);
    let mut cfg = FirewallConfig::default();
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("sharedaccess\\parameters\\firewallpolicy")
    }) {
        let leaf = key_leaf(&record.path).to_ascii_lowercase();
        let enabled = record
            .values
            .get("EnableFirewall")
            .and_then(|v| parse_reg_u32(v))
            .unwrap_or(0)
            != 0;
        if leaf.contains("domainprofile") {
            cfg.domain_profile = enabled;
        } else if leaf.contains("privateprofile") {
            cfg.private_profile = enabled;
        } else if leaf.contains("publicprofile") {
            cfg.public_profile = enabled;
        }
    }
    cfg
}

#[derive(Debug, Clone, Default)]
pub struct FirewallConfig {
    pub domain_profile: bool,
    pub private_profile: bool,
    pub public_profile: bool,
}

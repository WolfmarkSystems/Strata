use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

pub fn get_firewall_domain_profile() -> Result<FirewallProfile, ForensicError> {
    let path = env::var("FORENSIC_FIREWALL_DOMAIN_PROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("firewall")
                .join("domain_profile.json")
        });
    let Ok(data) = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
    else {
        return Ok(FirewallProfile {
            enabled: false,
            default_action: "block".to_string(),
        });
    };
    let Ok(v) = serde_json::from_slice::<Value>(&data) else {
        return Ok(FirewallProfile {
            enabled: false,
            default_action: "block".to_string(),
        });
    };
    Ok(FirewallProfile {
        enabled: v.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        default_action: v
            .get("default_action")
            .and_then(Value::as_str)
            .unwrap_or("block")
            .to_string(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct FirewallProfile {
    pub enabled: bool,
    pub default_action: String,
}

pub fn get_firewall_rules_count() -> u32 {
    let path = env::var("FORENSIC_FIREWALL_RULES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("firewall")
                .join("rules.json")
        });
    let Ok(data) = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
    else {
        return 0;
    };
    let Ok(v) = serde_json::from_slice::<Value>(&data) else {
        return 0;
    };
    if let Some(items) = v.as_array() {
        items.len() as u32
    } else if let Some(n) = v.get("count").and_then(Value::as_u64) {
        n as u32
    } else {
        0
    }
}

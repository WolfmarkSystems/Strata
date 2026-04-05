use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use std::env;
use std::path::PathBuf;

pub fn get_iis_config() -> IisConfig {
    let path = env::var("FORENSIC_IIS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("iis")
                .join("applicationHost.config")
        });
    let content = match read_text_prefix(&path, DEFAULT_TEXT_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return IisConfig::default(),
    };
    parse_iis_config_text(&content)
}

pub fn parse_iis_config_text(content: &str) -> IisConfig {
    let lower = content.to_ascii_lowercase();
    let mut version = String::new();

    if lower.contains("iis 10") || lower.contains("version=\"10") {
        version = "10".to_string();
    } else if lower.contains("iis 8") || lower.contains("version=\"8") {
        version = "8".to_string();
    } else if lower.contains("iis 7") || lower.contains("version=\"7") {
        version = "7".to_string();
    }

    if version.is_empty() && lower.contains("<system.applicationhost>") {
        version = "unknown-iis".to_string();
    }

    IisConfig { version }
}

#[derive(Debug, Clone, Default)]
pub struct IisConfig {
    pub version: String,
}

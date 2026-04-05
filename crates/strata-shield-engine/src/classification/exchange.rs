use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_exchange_config() -> ExchangeConfig {
    let path = env::var("FORENSIC_EXCHANGE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("exchange")
                .join("exchange_config.json")
        });
    let data = match super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return ExchangeConfig::default(),
    };
    let json: Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return ExchangeConfig::default(),
    };
    ExchangeConfig {
        server_name: json
            .get("server_name")
            .and_then(Value::as_str)
            .or_else(|| json.get("server").and_then(Value::as_str))
            .unwrap_or_default()
            .to_string(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExchangeConfig {
    pub server_name: String,
}

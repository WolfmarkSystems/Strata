use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_netcrypto_policies() -> CryptoPolicy {
    let path = path("FORENSIC_CRYPTO_POLICY", "crypto_policy.json");
    let data = match super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return CryptoPolicy::default(),
    };
    let json: Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return CryptoPolicy::default(),
    };
    CryptoPolicy {
        min_tls_version: n(&json, &["min_tls_version", "tls_min_version"]).unwrap_or_default(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct CryptoPolicy {
    pub min_tls_version: u16,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("security").join(file))
}

fn n(v: &Value, keys: &[&str]) -> Option<u16> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            if let Ok(out) = u16::try_from(x) {
                return Some(out);
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            let normalized = x.replace('.', "");
            if let Ok(out) = normalized.parse::<u16>() {
                return Some(out);
            }
        }
    }
    None
}

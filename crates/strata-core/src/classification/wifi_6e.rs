use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_wifi6e_networks() -> Vec<Wifi6eNetwork> {
    let Some(items) = load(path("FORENSIC_WIFI6E_NETWORKS", "wifi6e_networks.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| Wifi6eNetwork {
            ssid: s(&v, &["ssid"]),
            bssid: s(&v, &["bssid"]),
            channel: n(&v, &["channel"]) as u32,
            band: s(&v, &["band"]),
            security: s(&v, &["security"]),
            last_connected: n(&v, &["last_connected", "timestamp"]),
        })
        .filter(|x| !x.ssid.is_empty() || !x.bssid.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct Wifi6eNetwork {
    pub ssid: String,
    pub bssid: String,
    pub channel: u32,
    pub band: String,
    pub security: String,
    pub last_connected: u64,
}

pub fn get_wpa3_connections() -> Vec<Wpa3Connection> {
    let Some(items) = load(path("FORENSIC_WPA3_CONNECTIONS", "wpa3_connections.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| Wpa3Connection {
            ssid: s(&v, &["ssid"]),
            bssid: s(&v, &["bssid"]),
            auth_type: s(&v, &["auth_type", "authentication"]),
            key_exchange: s(&v, &["key_exchange"]),
            connected: n(&v, &["connected", "timestamp"]),
        })
        .filter(|x| !x.ssid.is_empty() || !x.bssid.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct Wpa3Connection {
    pub ssid: String,
    pub bssid: String,
    pub auth_type: String,
    pub key_exchange: String,
    pub connected: u64,
}

pub fn get_wifi_credentials() -> Vec<WifiCredential> {
    let Some(items) = load(path("FORENSIC_WIFI_CREDENTIALS", "wifi_credentials.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WifiCredential {
            ssid: s(&v, &["ssid"]),
            auth_type: s(&v, &["auth_type", "authentication"]),
            eap_method: opt_s(&v, &["eap_method"]),
        })
        .filter(|x| !x.ssid.is_empty() || !x.auth_type.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WifiCredential {
    pub ssid: String,
    pub auth_type: String,
    pub eap_method: Option<String>,
}

pub fn get_wifi_events() -> Vec<WifiEvent> {
    let Some(items) = load(path("FORENSIC_WIFI_EVENTS", "wifi_events.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WifiEvent {
            timestamp: n(&v, &["timestamp", "time"]),
            event_type: s(&v, &["event_type", "type"]),
            ssid: s(&v, &["ssid"]),
            bssid: s(&v, &["bssid"]),
            result: s(&v, &["result"]),
        })
        .filter(|x| x.timestamp > 0 || !x.event_type.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WifiEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub ssid: String,
    pub bssid: String,
    pub result: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("network").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let json: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = json.as_array() {
        Some(items.clone())
    } else if json.is_object() {
        Some(vec![json])
    } else {
        None
    }
}

fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}

fn opt_s(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return Some(x.to_string());
        }
    }
    None
}

fn n(v: &Value, keys: &[&str]) -> u64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return n;
            }
        }
    }
    0
}

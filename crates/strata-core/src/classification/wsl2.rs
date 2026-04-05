use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_wsl_distros() -> Vec<WslDistro> {
    let Some(items) = load(path("FORENSIC_WSL_DISTROS", "wsl_distros.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WslDistro {
            name: s(&v, &["name"]),
            version: n(&v, &["version"]) as u32,
            state: s(&v, &["state"]),
            default_user: s(&v, &["default_user"]),
        })
        .filter(|x| !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WslDistro {
    pub name: String,
    pub version: u32,
    pub state: String,
    pub default_user: String,
}

pub fn get_wsl_files() -> Vec<WslFile> {
    let Some(items) = load(path("FORENSIC_WSL_FILES", "wsl_files.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WslFile {
            distro: s(&v, &["distro"]),
            path: s(&v, &["path"]),
            size: n(&v, &["size"]),
            modified: n(&v, &["modified"]),
        })
        .filter(|x| !x.path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WslFile {
    pub distro: String,
    pub path: String,
    pub size: u64,
    pub modified: u64,
}

pub fn get_wsl_mounts() -> Vec<WslMount> {
    let Some(items) = load(path("FORENSIC_WSL_MOUNTS", "wsl_mounts.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WslMount {
            distro: s(&v, &["distro"]),
            mount_point: s(&v, &["mount_point"]),
            device: s(&v, &["device"]),
            options: s(&v, &["options"]),
        })
        .filter(|x| !x.mount_point.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WslMount {
    pub distro: String,
    pub mount_point: String,
    pub device: String,
    pub options: String,
}

pub fn get_wsl_config() -> Vec<WslConfig> {
    let Some(items) = load(path("FORENSIC_WSL_CONFIG", "wsl_config.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WslConfig {
            distro: s(&v, &["distro"]),
            memory: n(&v, &["memory"]) as u32,
            processors: n(&v, &["processors"]) as u32,
            swap: n(&v, &["swap"]) as u32,
        })
        .filter(|x| !x.distro.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WslConfig {
    pub distro: String,
    pub memory: u32,
    pub processors: u32,
    pub swap: u32,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("wsl").join(file))
}
fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
}
fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
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

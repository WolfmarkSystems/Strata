use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct InstallerPackage {
    pub product_code: String,
    pub product_name: String,
    pub manufacturer: String,
    pub version: String,
    pub install_date: Option<u64>,
    pub install_location: String,
    pub install_source: String,
    pub local_package: String,
    pub package_code: String,
}

pub fn get_installed_packages() -> Result<Vec<InstallerPackage>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_INSTALLER_PACKAGES",
        "installer_packages.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(parse_installer_package)
        .filter(|x| !x.product_code.is_empty() || !x.product_name.is_empty())
        .collect())
}

pub fn get_patch_packages() -> Result<Vec<InstallerPackage>, ForensicError> {
    let Some(items) = load(path("FORENSIC_INSTALLER_PATCHES", "installer_patches.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(parse_installer_package)
        .filter(|x| !x.product_code.is_empty() || !x.product_name.is_empty())
        .collect())
}

pub fn get_msi_component_cache() -> Result<Vec<ComponentCacheEntry>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_INSTALLER_COMPONENT_CACHE",
        "installer_component_cache.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| ComponentCacheEntry {
            component_id: s(&v, &["component_id", "id"]),
            component_path: s(&v, &["component_path", "path"]),
            dll_version: s_opt(&v, &["dll_version", "version"]),
            key_file: s(&v, &["key_file"]),
        })
        .filter(|x| !x.component_id.is_empty() || !x.component_path.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct ComponentCacheEntry {
    pub component_id: String,
    pub component_path: String,
    pub dll_version: Option<String>,
    pub key_file: String,
}

pub fn get_installer_log_locations() -> Vec<String> {
    vec![
        r"C:\Windows\Temp".to_string(),
        r"C:\Windows\Logs\WindowsUpdate".to_string(),
    ]
}

pub fn parse_installer_log(log_path: &str) -> Result<Vec<InstallerLogEntry>, ForensicError> {
    let Some(items) = load(PathBuf::from(log_path)) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| InstallerLogEntry {
            timestamp: n(&v, &["timestamp", "time"]),
            level: s(&v, &["level"]),
            message: s(&v, &["message"]),
            source: s(&v, &["source"]),
        })
        .filter(|x| x.timestamp > 0 || !x.message.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct InstallerLogEntry {
    pub timestamp: u64,
    pub level: String,
    pub message: String,
    pub source: String,
}

pub fn get_rollback_information() -> Result<Vec<RollbackInfo>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_INSTALLER_ROLLBACK",
        "installer_rollback.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| RollbackInfo {
            product_name: s(&v, &["product_name", "name"]),
            rollback_size: n(&v, &["rollback_size", "size"]),
            creation_time: n(&v, &["creation_time", "timestamp"]),
        })
        .filter(|x| !x.product_name.is_empty() || x.creation_time > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct RollbackInfo {
    pub product_name: String,
    pub rollback_size: u64,
    pub creation_time: u64,
}

fn parse_installer_package(v: Value) -> InstallerPackage {
    InstallerPackage {
        product_code: s(&v, &["product_code", "code"]),
        product_name: s(&v, &["product_name", "name"]),
        manufacturer: s(&v, &["manufacturer", "vendor"]),
        version: s(&v, &["version"]),
        install_date: opt_n(&v, &["install_date", "installed_at"]),
        install_location: s(&v, &["install_location", "location"]),
        install_source: s(&v, &["install_source", "source"]),
        local_package: s(&v, &["local_package"]),
        package_code: s(&v, &["package_code"]),
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("installer").join(file))
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

fn s_opt(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return Some(x.to_string());
        }
    }
    None
}

fn n(v: &Value, keys: &[&str]) -> u64 {
    opt_n(v, keys).unwrap_or(0)
}

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return Some(x as u64);
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

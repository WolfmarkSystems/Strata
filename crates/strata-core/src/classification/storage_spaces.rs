use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_storage_pools() -> Vec<StoragePool> {
    let Some(items) = load(path("FORENSIC_STORAGE_POOLS", "storage_pools.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| StoragePool {
            name: s(&v, &["name"]),
            friendly_name: s(&v, &["friendly_name"]),
            pool_id: s(&v, &["pool_id", "id"]),
            total_size: n(&v, &["total_size", "size"]),
            used_size: n(&v, &["used_size"]),
            health: s(&v, &["health", "status"]),
        })
        .filter(|x| !x.name.is_empty() || !x.pool_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct StoragePool {
    pub name: String,
    pub friendly_name: String,
    pub pool_id: String,
    pub total_size: u64,
    pub used_size: u64,
    pub health: String,
}

pub fn get_virtual_disks() -> Vec<VirtualDisk> {
    let Some(items) = load(path("FORENSIC_VIRTUAL_DISKS", "virtual_disks.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| VirtualDisk {
            name: s(&v, &["name"]),
            friendly_name: s(&v, &["friendly_name"]),
            disk_id: s(&v, &["disk_id", "id"]),
            parent_pool: s(&v, &["parent_pool", "pool"]),
            size: n(&v, &["size"]),
            health: s(&v, &["health", "status"]),
            file_system: s(&v, &["file_system", "fs"]),
        })
        .filter(|x| !x.name.is_empty() || !x.disk_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct VirtualDisk {
    pub name: String,
    pub friendly_name: String,
    pub disk_id: String,
    pub parent_pool: String,
    pub size: u64,
    pub health: String,
    pub file_system: String,
}

pub fn get_storage_tiers() -> Vec<StorageTier> {
    let Some(items) = load(path("FORENSIC_STORAGE_TIERS", "storage_tiers.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| StorageTier {
            name: s(&v, &["name"]),
            media_type: s(&v, &["media_type"]),
            size: n(&v, &["size"]),
            is_enabled: b(&v, &["is_enabled", "enabled"]),
        })
        .filter(|x| !x.name.is_empty() || x.size > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct StorageTier {
    pub name: String,
    pub media_type: String,
    pub size: u64,
    pub is_enabled: bool,
}

pub fn get_refs_volume() -> Vec<RefsVolume> {
    let Some(items) = load(path("FORENSIC_REFS_VOLUMES", "refs_volumes.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| RefsVolume {
            volume_guid: s(&v, &["volume_guid", "guid"]),
            mount_point: s(&v, &["mount_point"]),
            total_size: n(&v, &["total_size", "size"]),
            free_space: n(&v, &["free_space"]),
            is_metadata_defragmented: b(&v, &["is_metadata_defragmented", "metadata_defragmented"]),
        })
        .filter(|x| !x.volume_guid.is_empty() || !x.mount_point.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct RefsVolume {
    pub volume_guid: String,
    pub mount_point: String,
    pub total_size: u64,
    pub free_space: u64,
    pub is_metadata_defragmented: bool,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("storage").join(file))
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

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}

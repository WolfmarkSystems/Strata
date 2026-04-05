use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, key_leaf, load_reg_records};

pub fn get_volume_devices() -> Vec<VolumeDevice> {
    get_volume_devices_from_reg(&default_reg_path("disk.reg"))
}

pub fn get_volume_devices_from_reg(path: &Path) -> Vec<VolumeDevice> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\mounteddevices"))
    {
        for (name, raw) in &record.values {
            out.push(VolumeDevice {
                device_name: name.clone(),
                mount_point: name.clone(),
                volume_guid: decode_reg_string(raw).unwrap_or_default(),
            });
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct VolumeDevice {
    pub device_name: String,
    pub mount_point: String,
    pub volume_guid: String,
}

pub fn get_disk_drivers() -> Vec<DiskDriver> {
    get_disk_drivers_from_reg(&default_reg_path("disk.reg"))
}

pub fn get_disk_drivers_from_reg(path: &Path) -> Vec<DiskDriver> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\services\\disk"))
    {
        out.push(DiskDriver {
            device_name: key_leaf(&record.path),
            driver_key: record.path.clone(),
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct DiskDriver {
    pub device_name: String,
    pub driver_key: String,
}

pub fn get_storage_devices() -> Vec<StorageDevice> {
    get_storage_devices_from_reg(&default_reg_path("disk.reg"))
}

pub fn get_storage_devices_from_reg(path: &Path) -> Vec<StorageDevice> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("\\enum\\scsi\\") || p.contains("\\enum\\ide\\")
    }) {
        out.push(StorageDevice {
            model: record
                .values
                .get("FriendlyName")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| key_leaf(&record.path)),
            serial: record
                .values
                .get("SerialNumber")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct StorageDevice {
    pub model: String,
    pub serial: String,
}

use std::collections::BTreeMap;

use super::regusb;

pub fn get_usb_device_history() -> Vec<UsbHistoryEntry> {
    let mut by_device: BTreeMap<String, UsbHistoryEntry> = BTreeMap::new();

    for dev in regusb::get_usb_devices_full() {
        let key = if dev.device_desc.is_empty() {
            dev.serial.unwrap_or_else(|| "unknown-usb".to_string())
        } else {
            dev.device_desc
        };
        by_device.entry(key.clone()).or_insert(UsbHistoryEntry {
            device_name: key,
            first_connected: 0,
            last_connected: 0,
        });
    }

    for stor in regusb::get_usb_stor_devices() {
        let key = if stor.device.is_empty() {
            stor.serial
        } else {
            stor.device
        };
        by_device.entry(key.clone()).or_insert(UsbHistoryEntry {
            device_name: key,
            first_connected: 0,
            last_connected: 0,
        });
    }

    by_device.into_values().collect()
}

#[derive(Debug, Clone, Default)]
pub struct UsbHistoryEntry {
    pub device_name: String,
    pub first_connected: u64,
    pub last_connected: u64,
}

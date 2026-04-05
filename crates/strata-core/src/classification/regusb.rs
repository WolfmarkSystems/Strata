use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, key_leaf, load_reg_records};

pub fn get_usb_controllers() -> Vec<UsbController> {
    get_usb_controllers_from_reg(&default_reg_path("usb.reg"))
}

pub fn get_usb_controllers_from_reg(path: &Path) -> Vec<UsbController> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\enum\\usb\\"))
    {
        let name = record
            .values
            .get("DeviceDesc")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| key_leaf(&record.path));
        out.push(UsbController {
            name,
            device_id: key_leaf(&record.path),
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct UsbController {
    pub name: String,
    pub device_id: String,
}

pub fn get_usb_devices_full() -> Vec<UsbDeviceFull> {
    get_usb_devices_full_from_reg(&default_reg_path("usb.reg"))
}

pub fn get_usb_devices_full_from_reg(path: &Path) -> Vec<UsbDeviceFull> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\enum\\usb\\"))
    {
        let key = key_leaf(&record.path);
        let hardware_id = extract_usb_hardware_id(&record.path).unwrap_or_default();
        let (path_vid, path_pid) = parse_vid_pid(&record.path);
        let (value_vid, value_pid) = parse_vid_pid_from_values(&record.values);
        let vendor_id = path_vid.or(value_vid).unwrap_or_default();
        let product_id = path_pid.or(value_pid).unwrap_or_default();
        let device_desc = record
            .values
            .get("DeviceDesc")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| {
                record
                    .values
                    .get("FriendlyName")
                    .and_then(|v| decode_reg_string(v))
            })
            .map(|v| normalize_device_desc(&v))
            .unwrap_or_default();
        let serial = record
            .values
            .get("ParentIdPrefix")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| (!key.is_empty()).then_some(key.clone()))
            .map(|v| normalize_serial(&v));
        out.push(UsbDeviceFull {
            device_desc,
            service: record
                .values
                .get("Service")
                .and_then(|v| decode_reg_string(v))
                .map(|v| v.trim().to_string())
                .unwrap_or_default(),
            class: record
                .values
                .get("Class")
                .and_then(|v| decode_reg_string(v))
                .map(|v| v.trim().to_string())
                .unwrap_or_default(),
            vendor_id,
            product_id,
            serial,
            hardware_id,
        });
    }

    dedupe_usb_devices(out)
}

#[derive(Debug, Clone, Default)]
pub struct UsbDeviceFull {
    pub device_desc: String,
    pub service: String,
    pub class: String,
    pub vendor_id: String,
    pub product_id: String,
    pub serial: Option<String>,
    pub hardware_id: String,
}

pub fn get_usb_stor_devices() -> Vec<UsbStorage> {
    get_usb_stor_devices_from_reg(&default_reg_path("usb.reg"))
}

pub fn get_usb_stor_devices_from_reg(path: &Path) -> Vec<UsbStorage> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\enum\\usbstor\\"))
    {
        out.push(UsbStorage {
            device: record
                .values
                .get("FriendlyName")
                .and_then(|v| decode_reg_string(v))
                .map(|v| normalize_device_desc(&v))
                .unwrap_or_else(|| key_leaf(&record.path)),
            serial: key_leaf(&record.path),
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct UsbStorage {
    pub device: String,
    pub serial: String,
}

fn parse_vid_pid(text: &str) -> (Option<String>, Option<String>) {
    let lower = text.to_ascii_lowercase();
    let vid = parse_hex_quad_after(&lower, "vid_");
    let pid = parse_hex_quad_after(&lower, "pid_");
    (vid, pid)
}

fn parse_vid_pid_from_values(
    values: &std::collections::BTreeMap<String, String>,
) -> (Option<String>, Option<String>) {
    for key in ["HardwareID", "CompatibleIDs", "DeviceDesc"] {
        if let Some(raw) = values.get(key).and_then(|v| decode_reg_string(v)) {
            let parsed = parse_vid_pid(&raw);
            if parsed.0.is_some() || parsed.1.is_some() {
                return parsed;
            }
        }
    }
    (None, None)
}

fn parse_hex_quad_after(text: &str, marker: &str) -> Option<String> {
    let idx = text.find(marker)?;
    let candidate = text.get(idx + marker.len()..idx + marker.len() + 4)?;
    candidate
        .chars()
        .all(|c| c.is_ascii_hexdigit())
        .then(|| candidate.to_ascii_uppercase())
}

fn extract_usb_hardware_id(path: &str) -> Option<String> {
    let mut parts = path.split('\\');
    while let Some(part) = parts.next() {
        if part.eq_ignore_ascii_case("usb") {
            return parts.next().map(|s| s.to_string());
        }
    }
    None
}

fn normalize_device_desc(text: &str) -> String {
    let trimmed = text.trim().trim_matches('"');
    if let Some((_, rhs)) = trimmed.rsplit_once(';') {
        return rhs.trim().to_string();
    }
    trimmed.to_string()
}

fn normalize_serial(text: &str) -> String {
    text.trim()
        .trim_matches('"')
        .trim_start_matches('&')
        .to_string()
}

fn dedupe_usb_devices(rows: Vec<UsbDeviceFull>) -> Vec<UsbDeviceFull> {
    let mut seen = std::collections::BTreeSet::new();
    rows.into_iter()
        .filter(|row| {
            seen.insert(format!(
                "{}|{}|{}",
                row.hardware_id.to_ascii_lowercase(),
                row.vendor_id.to_ascii_lowercase(),
                row.serial.as_deref().unwrap_or("").to_ascii_lowercase()
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_usb_entries() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("usb.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_0781&PID_5591\1234]
"DeviceDesc"="SanDisk USB"
"Service"="USBSTOR"
"Class"="DiskDrive"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer\5678]
"FriendlyName"="SanDisk Cruzer"
"#,
        )
        .unwrap();
        let usb_rows = get_usb_devices_full_from_reg(&file);
        assert_eq!(usb_rows.len(), 1);
        assert_eq!(usb_rows[0].vendor_id, "0781");
        assert_eq!(usb_rows[0].product_id, "5591");
        assert_eq!(usb_rows[0].hardware_id, "VID_0781&PID_5591");
        assert_eq!(get_usb_stor_devices_from_reg(&file).len(), 1);
    }

    #[test]
    fn parse_usb_entries_with_inf_style_desc() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("usb.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_046D&PID_C52B\A123]
"DeviceDesc"="@usb.inf,%usb\vid_046d&pid_c52b.devicedesc%;Logitech USB Receiver"
"Service"="HidUsb"
"Class"="HIDClass"
"#,
        )
        .unwrap();

        let usb_rows = get_usb_devices_full_from_reg(&file);
        assert_eq!(usb_rows.len(), 1);
        assert_eq!(usb_rows[0].device_desc, "Logitech USB Receiver");
        assert_eq!(usb_rows[0].vendor_id, "046D");
        assert_eq!(usb_rows[0].product_id, "C52B");
        assert_eq!(usb_rows[0].serial.as_deref(), Some("A123"));
    }

    #[test]
    fn parse_usb_entries_uses_hardwareid_value_when_path_lacks_vid_pid() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("usb.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\Composite\ABC1]
"DeviceDesc"="USB Composite Device"
"HardwareID"="USB\VID_1234&PID_ABCD&REV_0100"
"Service"="usbccgp"
"#,
        )
        .unwrap();

        let rows = get_usb_devices_full_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].vendor_id, "1234");
        assert_eq!(rows[0].product_id, "ABCD");
    }

    #[test]
    fn parse_usb_entries_dedupes_and_falls_back_to_friendly_name() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("usb.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_1111&PID_2222\SER123]
"FriendlyName"="ACME Device"
"ParentIdPrefix"="SER123"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_1111&PID_2222\SER123]
"FriendlyName"="ACME Device Duplicate"
"ParentIdPrefix"="SER123"
"#,
        )
        .unwrap();

        let rows = get_usb_devices_full_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_desc, "ACME Device");
        assert_eq!(rows[0].serial.as_deref(), Some("SER123"));
    }
}

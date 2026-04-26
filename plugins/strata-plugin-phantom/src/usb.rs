//! Typed USB device-history parser for the SYSTEM hive.
//!
//! Walks both `CurrentControlSet\Enum\USBSTOR` (mass-storage devices) and
//! `CurrentControlSet\Enum\USB` (peripherals — keyboards, cameras,
//! adapters) and emits one [`UsbDeviceEntry`] per `serial_number`.
//!
//! ## USBSTOR layout
//!
//! ```text
//! USBSTOR
//! └── Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00     ← device_type (level 1)
//!     └── 4C530001120508111375&0                ← serial_number (level 2)
//!         ├── (values: FriendlyName, DeviceDesc, Driver, ...)
//!         └── Properties
//!             ├── {83da6326-…}\0064  (first-install FILETIME)
//!             ├── {83da6326-…}\0066  (last-connect  FILETIME)
//!             └── {83da6326-…}\0067  (last-removal  FILETIME)
//! ```
//!
//! The first level encodes both vendor and product as
//! `Disk&Ven_<VENDOR>&Prod_<PRODUCT>&Rev_<REV>`. We split it apart for
//! the typed struct so consumers don't have to re-parse strings.
//!
//! ## USB layout
//!
//! `Enum\USB` mirrors USBSTOR but for non-storage classes. The first
//! level is `VID_<vid>&PID_<pid>` (e.g. `VID_046D&PID_C52B` is a
//! Logitech receiver). Same per-device-instance second level.
//!
//! ## Forensic significance
//!
//! USB device history is the canonical evidence chain for
//! T1052.001 (Exfiltration over USB) and is also frequently the only
//! record that proves a specific physical device touched a host. The
//! `serial_number` is unique per physical unit (when honest) and is
//! the join key against external chain-of-custody tags.
//!
//! Generic / all-zero serial numbers indicate either a non-compliant
//! device or a deliberately spoofed identity — both red flags.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// FILETIME → Unix epoch difference, in 100-nanosecond intervals.
const FILETIME_EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
/// Hard cap on USB devices returned per hive scan. Real hosts have
/// <100 lifetime devices; 4096 is a safety bound.
const MAX_DEVICES: usize = 4096;

/// Bus type for a typed USB device entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbBus {
    /// Mass-storage class (`Enum\USBSTOR`). Sticks, external HDDs, SD
    /// readers, phones in MTP mode register here.
    Storage,
    /// Generic USB (`Enum\USB`). Keyboards, mice, webcams, MIDI, network
    /// adapters, hubs, BadUSB devices.
    Generic,
}

impl UsbBus {
    pub fn as_str(&self) -> &'static str {
        match self {
            UsbBus::Storage => "USBSTOR",
            UsbBus::Generic => "USB",
        }
    }
}

/// One typed USB device-history entry.
///
/// Field meanings are forensic-first; downstream consumers (Phantom,
/// Sigma rules, the timeline view) read these without having to know
/// the registry layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDeviceEntry {
    /// Which USB Enum sub-tree the device was found under — `USBSTOR`
    /// (mass-storage) or `USB` (peripherals). Critical for reasoning
    /// about the device's role: a `USBSTOR` device with last-connect
    /// minutes before file deletion is very different from a `USB`
    /// keyboard.
    pub bus: UsbBus,

    /// First-level Enum subkey name verbatim (e.g.
    /// `"Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00"` or
    /// `"VID_046D&PID_C52B"`). Preserved as-is so the analyst can
    /// cross-reference with vendor/product databases.
    pub device_type: String,

    /// Vendor parsed from `device_type`. For USBSTOR this is the
    /// substring after `Ven_` and before `&`; for USB it is the 4-hex
    /// `VID` value. Empty when the layout doesn't match either pattern.
    pub vendor: String,

    /// Product parsed from `device_type`. For USBSTOR this is the
    /// substring after `Prod_` and before `&Rev_`; for USB it is the
    /// 4-hex `PID` value. Empty when missing.
    pub product: String,

    /// Per-device-instance serial number (the second-level subkey
    /// name). Unique per physical unit when the firmware is honest.
    /// `serial_number` ending in `&0` indicates a Microsoft-generated
    /// fallback (the device did not advertise a serial), which itself
    /// is a useful signal — see [`is_generic_serial`].
    pub serial_number: String,

    /// `FriendlyName` REG_SZ value, e.g. `"SanDisk Cruzer USB Device"`.
    /// User-visible label Windows shows in Explorer.
    pub friendly_name: String,

    /// `DeviceDesc` REG_SZ value, e.g.
    /// `"@disk.inf,%disk_devdesc%;Disk drive"`. Less friendly than
    /// `FriendlyName` but always populated.
    pub device_desc: String,

    /// Drive letter assigned to the device, when present (USBSTOR
    /// only). Sourced from the `DriveLetter` value when Windows
    /// exposes it. `None` for peripherals and for storage devices that
    /// were never mounted by this OS.
    pub drive_letter: Option<String>,

    /// Best-available "last write" timestamp for the device's per-
    /// instance subkey. nt-hive 0.3.0 does not expose the registry
    /// key's native `LastWriteTime` field, so we fall back to the
    /// Properties\{83da6326-…}\0066 (last-connect) FILETIME, then to
    /// 0064 (first-install) when the connect slot is missing. Returns
    /// `None` when neither is present.
    pub last_write_time: Option<DateTime<Utc>>,

    /// Properties\…\0064 — first time Windows ever installed a driver
    /// for this device instance. Definitive "first seen" evidence.
    pub first_install_time: Option<DateTime<Utc>>,

    /// Properties\…\0066 — most recent connection. The single most
    /// useful timestamp for "was this device plugged in during the
    /// incident window" questions.
    pub last_connect_time: Option<DateTime<Utc>>,

    /// Properties\…\0067 — most recent removal. Pair with the file-
    /// system `MoveOnReboot` and `$UsnJrnl` entries for "device
    /// disconnected before file delete" patterns.
    pub last_removal_time: Option<DateTime<Utc>>,
}

/// Result of parsing the USB device history from a SYSTEM hive root
/// node. Empty (`devices.is_empty()`) when neither USBSTOR nor USB
/// trees are present.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsbHistory {
    pub devices: Vec<UsbDeviceEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsbDeviceRecord {
    pub vendor: String,
    pub product: String,
    pub serial: String,
    pub vid_pid: String,
    pub drive_letter: Option<String>,
    pub volume_guid: Option<String>,
    pub first_insert: Option<i64>,
    pub last_insert: Option<i64>,
    pub user_connected: Vec<String>,
}

/// Heuristic: serial numbers that look spoofed / Microsoft-generated.
/// Forensically-actionable categories:
/// * all zeros (or all repeating the same hex digit)
/// * ending in `&0` (Windows-assigned fallback when device is silent)
/// * fewer than 4 chars (no real-world device uses such short serials)
pub fn is_generic_serial(serial: &str) -> bool {
    if serial.len() < 4 {
        return true;
    }
    if serial.ends_with("&0") || serial.ends_with("&1") {
        return true;
    }
    let body = serial.trim_end_matches(char::is_alphanumeric).to_string();
    let _ = body; // unused — left for future-version heuristics
    let alnum: String = serial.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if alnum.len() >= 8 {
        let first = alnum.chars().next();
        if let Some(c) = first {
            if alnum.chars().all(|ch| ch == c) {
                return true;
            }
        }
    }
    false
}

pub fn serial_from_usbstor_key(key: &str) -> String {
    key.rsplit('\\')
        .next()
        .unwrap_or(key)
        .split('&')
        .next()
        .unwrap_or("")
        .to_string()
}

pub fn parse_setupapi_first_insert(log: &str, serial: &str) -> Option<i64> {
    let mut in_device = false;
    for line in log.lines() {
        if line.contains("Device Install")
            && line.to_ascii_uppercase().contains("USBSTOR")
            && line.contains(serial)
        {
            in_device = true;
            continue;
        }
        if in_device && line.contains("Section start") {
            let ts = line.split("Section start").nth(1)?.trim();
            return parse_setupapi_timestamp(ts);
        }
    }
    None
}

pub fn parse_setupapi_timestamp(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    let naive = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y/%m/%d %H:%M:%S%.f").ok()?;
    Some(naive.and_utc().timestamp())
}

pub fn deduplicate_records(records: Vec<UsbDeviceRecord>) -> Vec<UsbDeviceRecord> {
    let mut by_serial: HashMap<String, UsbDeviceRecord> = HashMap::new();
    for record in records {
        let key = record.serial.clone();
        by_serial
            .entry(key)
            .and_modify(|existing| merge_record(existing, &record))
            .or_insert(record);
    }
    let mut out: Vec<_> = by_serial.into_values().collect();
    out.sort_by(|a, b| a.serial.cmp(&b.serial));
    out
}

fn merge_record(existing: &mut UsbDeviceRecord, next: &UsbDeviceRecord) {
    if existing.vendor.is_empty() {
        existing.vendor = next.vendor.clone();
    }
    if existing.product.is_empty() {
        existing.product = next.product.clone();
    }
    if existing.vid_pid.is_empty() {
        existing.vid_pid = next.vid_pid.clone();
    }
    if existing.drive_letter.is_none() {
        existing.drive_letter = next.drive_letter.clone();
    }
    if existing.volume_guid.is_none() {
        existing.volume_guid = next.volume_guid.clone();
    }
    existing.first_insert = match (existing.first_insert, next.first_insert) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (None, b) => b,
        (a, None) => a,
    };
    existing.last_insert = match (existing.last_insert, next.last_insert) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (None, b) => b,
        (a, None) => a,
    };
    for user in &next.user_connected {
        if !existing.user_connected.contains(user) {
            existing.user_connected.push(user.clone());
        }
    }
}

/// Parse the USB chain from the SYSTEM hive root. Walks both
/// `ControlSet001\Enum\USBSTOR` and `ControlSet001\Enum\USB`. Returns
/// an empty [`UsbHistory`] when neither tree is present.
///
/// Never panics, never calls `unwrap`, never invokes `unsafe`.
pub fn parse(root: &nt_hive::KeyNode<'_, &[u8]>) -> UsbHistory {
    let mut devices = Vec::new();
    if let Some(usbstor) = walk(root, &["ControlSet001", "Enum", "USBSTOR"]) {
        collect_devices(&usbstor, UsbBus::Storage, &mut devices);
    }
    if let Some(usb) = walk(root, &["ControlSet001", "Enum", "USB"]) {
        collect_devices(&usb, UsbBus::Generic, &mut devices);
    }
    UsbHistory { devices }
}

fn collect_devices(
    enum_root: &nt_hive::KeyNode<'_, &[u8]>,
    bus: UsbBus,
    out: &mut Vec<UsbDeviceEntry>,
) {
    let Some(level1_iter) = enum_root.subkeys() else {
        return;
    };
    let Ok(level1_iter) = level1_iter else {
        return;
    };
    for class_res in level1_iter {
        if out.len() >= MAX_DEVICES {
            return;
        }
        let Ok(class_node) = class_res else { continue };
        let Ok(class_name_raw) = class_node.name() else {
            continue;
        };
        let device_type = class_name_raw.to_string_lossy();
        let (vendor, product) = parse_vendor_product(&device_type, bus);

        let Some(level2_iter) = class_node.subkeys() else {
            continue;
        };
        let Ok(level2_iter) = level2_iter else {
            continue;
        };
        for instance_res in level2_iter {
            if out.len() >= MAX_DEVICES {
                return;
            }
            let Ok(instance_node) = instance_res else {
                continue;
            };
            let Ok(serial_raw) = instance_node.name() else {
                continue;
            };
            let serial_number = serial_raw.to_string_lossy();

            let friendly_name =
                read_value_string(&instance_node, "FriendlyName").unwrap_or_default();
            let device_desc = read_value_string(&instance_node, "DeviceDesc").unwrap_or_default();
            let drive_letter =
                read_value_string(&instance_node, "DriveLetter").filter(|s| !s.is_empty());

            let (first_install, last_connect, last_removal) = read_property_times(&instance_node);
            let last_write_time = last_connect.or(first_install);

            out.push(UsbDeviceEntry {
                bus,
                device_type: device_type.clone(),
                vendor: vendor.clone(),
                product: product.clone(),
                serial_number,
                friendly_name,
                device_desc,
                drive_letter,
                last_write_time,
                first_install_time: first_install,
                last_connect_time: last_connect,
                last_removal_time: last_removal,
            });
        }
    }
}

/// `(first_install, last_connect, last_removal)` triple in chrono UTC.
type PropertyTimes = (
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

/// Pull the three Properties timestamps for one USB device instance.
/// Properties live under either
/// `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\<NNNN>` (the GUID
/// for "device installation properties") or directly under
/// `Properties\<NNNN>` on older builds. Try both.
fn read_property_times(instance: &nt_hive::KeyNode<'_, &[u8]>) -> PropertyTimes {
    let Some(props) = instance.subkey("Properties").and_then(|r| r.ok()) else {
        return (None, None, None);
    };
    // Try the modern GUID-nested layout first.
    let guid_key = props
        .subkey("{83da6326-97a6-4088-9453-a1923f573b29}")
        .and_then(|r| r.ok());
    let direct_key = props;
    let lookup = |name: &str| -> Option<DateTime<Utc>> {
        if let Some(ref k) = guid_key {
            if let Some(ts) = read_filetime_value(k, name) {
                return Some(ts);
            }
        }
        // Walk one level down — older builds nest `Properties\<NNNN>`
        // under another GUID we don't enumerate by name. Scan all
        // first-level Properties subkeys.
        if let Some(Ok(iter)) = direct_key.subkeys() {
            for child_res in iter {
                let Ok(child) = child_res else { continue };
                if let Some(ts) = read_filetime_value(&child, name) {
                    return Some(ts);
                }
            }
        }
        None
    };
    (lookup("0064"), lookup("0066"), lookup("0067"))
}

fn read_filetime_value(node: &nt_hive::KeyNode<'_, &[u8]>, name: &str) -> Option<DateTime<Utc>> {
    let bytes = read_value_bytes(node, name)?;
    if bytes.len() < 8 {
        return None;
    }
    let arr = <[u8; 8]>::try_from(&bytes[0..8]).ok()?;
    filetime_to_datetime(i64::from_le_bytes(arr))
}

/// Split `device_type` into a `(vendor, product)` pair. Tolerant of
/// missing components — returns empty strings rather than `None`.
pub(crate) fn parse_vendor_product(device_type: &str, bus: UsbBus) -> (String, String) {
    match bus {
        UsbBus::Storage => {
            let vendor = extract_between(device_type, "Ven_", "&");
            let product = extract_between(device_type, "Prod_", "&");
            (vendor, product)
        }
        UsbBus::Generic => {
            let vid = extract_between(device_type, "VID_", "&");
            let pid = extract_between(device_type, "PID_", "&");
            (vid, pid)
        }
    }
}

/// Inclusive-after / exclusive-before substring extraction. Returns
/// `String::new()` on failure rather than `None` so the caller can use
/// it as a final value directly.
fn extract_between(haystack: &str, after: &str, before: &str) -> String {
    let Some(start) = haystack.find(after) else {
        return String::new();
    };
    let cursor = start + after.len();
    let Some(rest) = haystack.get(cursor..) else {
        return String::new();
    };
    if let Some(end) = rest.find(before) {
        rest[..end].to_string()
    } else {
        rest.to_string()
    }
}

// ── nt-hive value helpers (mirrored from the legacy `parsers` mod —
//    they're `pub(super)` there and not importable here) ────────────────

fn read_value_bytes(node: &nt_hive::KeyNode<'_, &[u8]>, value_name: &str) -> Option<Vec<u8>> {
    let values_iter = node.values()?.ok()?;
    for value_res in values_iter {
        let value = value_res.ok()?;
        let raw_name = value.name().ok()?;
        let name = raw_name.to_string_lossy();
        if name.eq_ignore_ascii_case(value_name) {
            let data = value.data().ok()?;
            return data.into_vec().ok();
        }
    }
    None
}

fn read_value_string(node: &nt_hive::KeyNode<'_, &[u8]>, value_name: &str) -> Option<String> {
    let bytes = read_value_bytes(node, value_name)?;
    let utf16 = utf16le_to_string(&bytes);
    if !utf16.is_empty() {
        return Some(utf16);
    }
    let ansi = String::from_utf8_lossy(&bytes)
        .trim_end_matches('\0')
        .to_string();
    if ansi.is_empty() {
        None
    } else {
        Some(ansi)
    }
}

fn utf16le_to_string(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&ch| ch != 0)
        .collect();
    String::from_utf16_lossy(&u16s)
}

fn walk<'a>(
    root: &nt_hive::KeyNode<'a, &'a [u8]>,
    path: &[&str],
) -> Option<nt_hive::KeyNode<'a, &'a [u8]>> {
    let mut node = root.clone();
    for part in path {
        node = node.subkey(part)?.ok()?;
    }
    Some(node)
}

/// Convert a Windows `FILETIME` (100-ns ticks since 1601-01-01 UTC) to
/// `DateTime<Utc>`. Returns `None` for the uninitialised slot (0) and
/// for values outside chrono's representable range.
pub(crate) fn filetime_to_datetime(ft: i64) -> Option<DateTime<Utc>> {
    if ft <= 0 {
        return None;
    }
    let unix_100ns = ft.checked_sub(FILETIME_EPOCH_DIFF_100NS)?;
    let unix_secs = unix_100ns / 10_000_000;
    let nanos_part = (unix_100ns % 10_000_000) * 100;
    let nanos = if (0..=i64::from(u32::MAX)).contains(&nanos_part) {
        nanos_part as u32
    } else {
        0
    };
    DateTime::<Utc>::from_timestamp(unix_secs, nanos)
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vendor_product_handles_usbstor_layout() {
        let s = "Disk&Ven_SanDisk&Prod_Cruzer_Glide&Rev_1.00";
        let (v, p) = parse_vendor_product(s, UsbBus::Storage);
        assert_eq!(v, "SanDisk");
        assert_eq!(p, "Cruzer_Glide");
    }

    #[test]
    fn parse_vendor_product_handles_usb_layout() {
        let s = "VID_046D&PID_C52B";
        let (vid, pid) = parse_vendor_product(s, UsbBus::Generic);
        assert_eq!(vid, "046D");
        assert_eq!(pid, "C52B");
    }

    #[test]
    fn parse_vendor_product_returns_empty_on_unrecognized_layout() {
        let (v, p) = parse_vendor_product("garbage_no_known_markers", UsbBus::Storage);
        assert_eq!(v, "");
        assert_eq!(p, "");
        let (vid, pid) = parse_vendor_product("ALSO_GARBAGE", UsbBus::Generic);
        assert_eq!(vid, "");
        assert_eq!(pid, "");
    }

    #[test]
    fn extract_between_returns_text_or_empty() {
        assert_eq!(
            extract_between("Ven_SanDisk&Prod_X", "Ven_", "&"),
            "SanDisk"
        );
        assert_eq!(extract_between("nothing", "Ven_", "&"), "");
        // No terminator → take rest.
        assert_eq!(extract_between("Ven_SanDisk", "Ven_", "&"), "SanDisk");
    }

    #[test]
    fn is_generic_serial_flags_short_or_zero_serials() {
        assert!(is_generic_serial(""));
        assert!(is_generic_serial("a"));
        assert!(is_generic_serial("abc"));
        assert!(is_generic_serial("00000000"));
        assert!(is_generic_serial("FFFFFFFF"));
        assert!(is_generic_serial("12345678&0"));
        assert!(!is_generic_serial("4C530001120508111375"));
        assert!(!is_generic_serial("NL2GH1JM"));
    }

    #[test]
    fn filetime_helper_round_trips_known_value() {
        // 2024-06-01 12:00:00 UTC = unix 1_717_243_200
        let ft = 1_717_243_200_i64 * 10_000_000 + FILETIME_EPOCH_DIFF_100NS;
        let dt = filetime_to_datetime(ft).expect("valid timestamp");
        assert_eq!(dt.timestamp(), 1_717_243_200);
    }

    #[test]
    fn filetime_zero_or_negative_returns_none() {
        assert!(filetime_to_datetime(0).is_none());
        assert!(filetime_to_datetime(-1).is_none());
    }

    #[test]
    fn usb_bus_as_str_round_trips() {
        assert_eq!(UsbBus::Storage.as_str(), "USBSTOR");
        assert_eq!(UsbBus::Generic.as_str(), "USB");
    }

    #[test]
    fn usb_history_default_is_empty() {
        let h = UsbHistory::default();
        assert!(h.devices.is_empty());
    }

    #[test]
    fn usb_serial_extracted_from_usbstor_key() {
        assert_eq!(
            serial_from_usbstor_key(
                r"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\4C530001120508111375&0"
            ),
            "4C530001120508111375"
        );
    }

    #[test]
    fn setupapi_timestamp_parsed_correctly() {
        assert_eq!(
            parse_setupapi_timestamp("2025/11/04 17:19:08.123"),
            Some(1_762_276_748)
        );
    }

    #[test]
    fn usb_records_deduplicated_by_serial() {
        let records = vec![
            UsbDeviceRecord {
                vendor: "SanDisk".to_string(),
                product: "Cruzer".to_string(),
                serial: "ABC123".to_string(),
                first_insert: Some(100),
                ..UsbDeviceRecord::default()
            },
            UsbDeviceRecord {
                serial: "ABC123".to_string(),
                drive_letter: Some("E:".to_string()),
                user_connected: vec!["alice".to_string()],
                last_insert: Some(200),
                ..UsbDeviceRecord::default()
            },
        ];
        let deduped = deduplicate_records(records);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].serial, "ABC123");
        assert_eq!(deduped[0].drive_letter.as_deref(), Some("E:"));
        assert_eq!(deduped[0].user_connected, vec!["alice"]);
    }
}

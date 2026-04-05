use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct UsbDevice {
    pub vendor_id: String,
    pub product_id: String,
    pub serial_number: Option<String>,
    pub friendly_name: Option<String>,
    pub first_install_date: Option<i64>,
    pub last_connected: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct UsbHistory {
    pub devices: Vec<UsbDevice>,
}

#[derive(Debug, Clone)]
pub struct UsbDeviceHistoryRecord {
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub serial_number: Option<String>,
    pub friendly_name: Option<String>,
    pub first_install_unix: Option<i64>,
    pub last_connected_unix: Option<i64>,
    pub timestamp_unix: Option<i64>,
    pub timestamp_utc: Option<String>,
    pub timestamp_precision: String,
    pub user_sid: Option<String>,
    pub username: Option<String>,
    pub device_instance_id: Option<String>,
    pub device_class: Option<String>,
    pub source_path: Option<String>,
    pub source_record_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbInputShape {
    Missing,
    Empty,
    Directory,
    JsonArray,
    JsonObject,
    CsvText,
    LineText,
    Unknown,
}

impl UsbInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::Directory => "directory",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::CsvText => "csv-text",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_usb_input_shape(path: &Path) -> UsbInputShape {
    if !path.exists() {
        return UsbInputShape::Missing;
    }
    if path.is_dir() {
        return UsbInputShape::Directory;
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return UsbInputShape::Unknown;
    };
    if bytes.is_empty() {
        return UsbInputShape::Empty;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return UsbInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return UsbInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return UsbInputShape::JsonObject;
    }
    let first = trimmed
        .lines()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if first.contains("vendor_id")
        || first.contains("product_id")
        || first.contains("serial")
        || first.contains("device_instance")
    {
        return UsbInputShape::CsvText;
    }
    UsbInputShape::LineText
}

pub fn parse_usb_records_from_path(path: &Path, limit: usize) -> Vec<UsbDeviceHistoryRecord> {
    if !path.exists() || limit == 0 {
        return Vec::new();
    }

    let mut rows = if path.is_dir() {
        parse_usb_dir(path, limit)
    } else {
        parse_usb_file(path)
    };
    if rows.is_empty() {
        rows = parse_usb_text_fallback(path);
    }

    let mut seen = BTreeSet::<String>::new();
    rows.retain(|row| {
        let key = format!(
            "{}|{}|{}|{}|{}",
            row.vendor_id.clone().unwrap_or_default(),
            row.product_id.clone().unwrap_or_default(),
            row.serial_number.clone().unwrap_or_default(),
            row.timestamp_unix
                .map(|v| v.to_string())
                .unwrap_or_default(),
            row.device_instance_id.clone().unwrap_or_default()
        );
        seen.insert(key)
    });

    rows.sort_by(|a, b| {
        b.timestamp_unix
            .is_some()
            .cmp(&a.timestamp_unix.is_some())
            .then_with(|| {
                b.timestamp_unix
                    .unwrap_or_default()
                    .cmp(&a.timestamp_unix.unwrap_or_default())
            })
            .then_with(|| {
                a.vendor_id
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(b.vendor_id.as_deref().unwrap_or_default())
            })
            .then_with(|| {
                a.product_id
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(b.product_id.as_deref().unwrap_or_default())
            })
    });
    rows.truncate(limit);
    rows
}

pub fn parse_usb_text_fallback(path: &Path) -> Vec<UsbDeviceHistoryRecord> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_usb_csv_or_lines(&content)
}

fn parse_usb_dir(path: &Path, limit: usize) -> Vec<UsbDeviceHistoryRecord> {
    let mut out = Vec::new();
    let Ok(entries) = strata_fs::read_dir(path) else {
        return out;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let mut nested = parse_usb_dir(&p, limit.saturating_sub(out.len()));
            out.append(&mut nested);
        } else {
            let mut rows = parse_usb_file(&p);
            out.append(&mut rows);
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn parse_usb_file(path: &Path) -> Vec<UsbDeviceHistoryRecord> {
    let Ok(bytes) = strata_fs::read(path) else {
        return Vec::new();
    };
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        return parse_usb_rows_json_value(&value);
    }
    parse_usb_csv_or_lines(String::from_utf8_lossy(&bytes).as_ref())
}

fn parse_usb_rows_json_value(value: &Value) -> Vec<UsbDeviceHistoryRecord> {
    let rows = if let Some(arr) = value.as_array() {
        arr.clone()
    } else if let Some(obj) = value.as_object() {
        obj.get("records")
            .and_then(|v| v.as_array())
            .or_else(|| obj.get("devices").and_then(|v| v.as_array()))
            .or_else(|| obj.get("history").and_then(|v| v.as_array()))
            .or_else(|| obj.get("entries").and_then(|v| v.as_array()))
            .or_else(|| obj.get("data").and_then(|v| v.as_array()))
            .cloned()
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let mut out = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else {
            continue;
        };

        let first_ts = parse_ts(
            obj.get("first_install_unix")
                .or_else(|| obj.get("first_install_date"))
                .or_else(|| obj.get("first_seen_unix"))
                .or_else(|| obj.get("first_seen_utc")),
        );
        let last_ts = parse_ts(
            obj.get("last_connected_unix")
                .or_else(|| obj.get("last_connected"))
                .or_else(|| obj.get("last_seen_unix"))
                .or_else(|| obj.get("last_seen_utc"))
                .or_else(|| obj.get("timestamp_unix"))
                .or_else(|| obj.get("timestamp"))
                .or_else(|| obj.get("occurred_utc")),
        );
        let timestamp = if last_ts.0.is_some() {
            last_ts.clone()
        } else {
            first_ts.clone()
        };

        out.push(UsbDeviceHistoryRecord {
            vendor_id: obj
                .get("vendor_id")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("vid").and_then(|v| v.as_str()))
                .map(normalize_hexish_id),
            product_id: obj
                .get("product_id")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("pid").and_then(|v| v.as_str()))
                .map(normalize_hexish_id),
            serial_number: obj
                .get("serial_number")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("serial").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            friendly_name: obj
                .get("friendly_name")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("name").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            first_install_unix: first_ts.0,
            last_connected_unix: last_ts.0,
            timestamp_unix: timestamp.0,
            timestamp_utc: timestamp.1,
            timestamp_precision: timestamp.2,
            user_sid: obj
                .get("user_sid")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("sid").and_then(|v| v.as_str()))
                .map(normalize_sid),
            username: obj
                .get("username")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("user").and_then(|v| v.as_str()))
                .map(normalize_username),
            device_instance_id: obj
                .get("device_instance_id")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("instance_id").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            device_class: obj
                .get("device_class")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("class").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty()),
            source_path: obj
                .get("source_path")
                .and_then(|v| v.as_str())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            source_record_id: obj
                .get("source_record_id")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("record_id").and_then(|v| v.as_str()))
                .or_else(|| obj.get("id").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
        });
    }
    out
}

fn parse_usb_csv_or_lines(content: &str) -> Vec<UsbDeviceHistoryRecord> {
    let mut out = Vec::new();
    let mut lines = content.lines();
    let first = lines.next().unwrap_or_default();
    let first_lc = first.to_ascii_lowercase();
    if first.contains(',')
        && (first_lc.contains("vendor_id")
            || first_lc.contains("product_id")
            || first_lc.contains("serial")
            || first_lc.contains("device_instance"))
    {
        let headers = first
            .split(',')
            .map(|v| v.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let cols = trimmed.split(',').map(|v| v.trim()).collect::<Vec<_>>();
            if cols.is_empty() {
                continue;
            }
            let get_col = |name: &str| -> Option<&str> {
                headers
                    .iter()
                    .position(|h| h == name)
                    .and_then(|idx| cols.get(idx).copied())
            };
            let first_ts = parse_ts_str(
                get_col("first_install_unix")
                    .or_else(|| get_col("first_install_date"))
                    .or_else(|| get_col("first_seen_unix"))
                    .or_else(|| get_col("first_seen_utc"))
                    .unwrap_or_default(),
            );
            let last_ts = parse_ts_str(
                get_col("last_connected_unix")
                    .or_else(|| get_col("last_connected"))
                    .or_else(|| get_col("last_seen_unix"))
                    .or_else(|| get_col("last_seen_utc"))
                    .or_else(|| get_col("timestamp_unix"))
                    .or_else(|| get_col("timestamp"))
                    .unwrap_or_default(),
            );
            let ts = if last_ts.0.is_some() {
                last_ts.clone()
            } else {
                first_ts.clone()
            };

            out.push(UsbDeviceHistoryRecord {
                vendor_id: get_col("vendor_id")
                    .or_else(|| get_col("vid"))
                    .map(normalize_hexish_id),
                product_id: get_col("product_id")
                    .or_else(|| get_col("pid"))
                    .map(normalize_hexish_id),
                serial_number: get_col("serial_number")
                    .or_else(|| get_col("serial"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                friendly_name: get_col("friendly_name")
                    .or_else(|| get_col("name"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                first_install_unix: first_ts.0,
                last_connected_unix: last_ts.0,
                timestamp_unix: ts.0,
                timestamp_utc: ts.1,
                timestamp_precision: ts.2,
                user_sid: get_col("user_sid")
                    .or_else(|| get_col("sid"))
                    .map(normalize_sid),
                username: get_col("username")
                    .or_else(|| get_col("user"))
                    .map(normalize_username),
                device_instance_id: get_col("device_instance_id")
                    .or_else(|| get_col("instance_id"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                device_class: get_col("device_class")
                    .or_else(|| get_col("class"))
                    .map(|v| v.to_ascii_lowercase())
                    .filter(|v| !v.is_empty()),
                source_path: get_col("source_path")
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                source_record_id: get_col("source_record_id")
                    .or_else(|| get_col("record_id"))
                    .or_else(|| get_col("id"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
            });
        }
        return out;
    }

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((vendor_product, serial)) = trimmed.split_once('|') {
            let mut parts = vendor_product.split(':');
            let vendor = parts.next().unwrap_or_default().trim();
            let product = parts.next().unwrap_or_default().trim();
            out.push(UsbDeviceHistoryRecord {
                vendor_id: if vendor.is_empty() {
                    None
                } else {
                    Some(normalize_hexish_id(vendor))
                },
                product_id: if product.is_empty() {
                    None
                } else {
                    Some(normalize_hexish_id(product))
                },
                serial_number: Some(serial.trim().to_string()).filter(|v| !v.is_empty()),
                friendly_name: None,
                first_install_unix: None,
                last_connected_unix: None,
                timestamp_unix: None,
                timestamp_utc: None,
                timestamp_precision: "none".to_string(),
                user_sid: None,
                username: None,
                device_instance_id: None,
                device_class: None,
                source_path: None,
                source_record_id: None,
            });
        }
    }
    out
}

fn parse_ts(value: Option<&Value>) -> (Option<i64>, Option<String>, String) {
    let Some(v) = value else {
        return (None, None, "none".to_string());
    };
    if let Some(n) = value_to_i64(v) {
        return normalize_epochish_ts(n);
    }
    if let Some(s) = v.as_str() {
        return parse_ts_str(s);
    }
    (None, None, "none".to_string())
}

fn parse_ts_str(value: &str) -> (Option<i64>, Option<String>, String) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return (None, None, "none".to_string());
    }
    if let Ok(v) = trimmed.parse::<i64>() {
        return normalize_epochish_ts(v);
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        let ts = dt.timestamp();
        return (Some(ts), Some(ts_to_utc(ts)), "seconds".to_string());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        let ts = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc)
            .timestamp();
        return (Some(ts), Some(ts_to_utc(ts)), "seconds".to_string());
    }
    (None, None, "none".to_string())
}

fn normalize_epochish_ts(value: i64) -> (Option<i64>, Option<String>, String) {
    if value <= 0 {
        return (None, None, "none".to_string());
    }
    let (ts, precision) = if value > 10_000_000_000 {
        (value / 1_000, "milliseconds".to_string())
    } else {
        (value, "seconds".to_string())
    };
    (Some(ts), Some(ts_to_utc(ts)), precision)
}

fn ts_to_utc(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}

fn value_to_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
        .or_else(|| value.as_str().and_then(|v| v.trim().parse::<i64>().ok()))
}

fn normalize_hexish_id(value: &str) -> String {
    value
        .trim()
        .to_ascii_uppercase()
        .trim_start_matches("VID_")
        .trim_start_matches("PID_")
        .to_string()
}

fn normalize_sid(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn normalize_username(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn parse_usb_registry(base_path: &Path) -> Result<UsbHistory, ForensicError> {
    let mut devices = Vec::new();

    let system_registry = base_path.join("SYSTEM");
    if !system_registry.exists() {
        return Ok(UsbHistory { devices });
    }

    if let Ok(entries) = strata_fs::read_dir(&system_registry) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("ControlSet") {
                        let enum_path = path.join("Enum").join("USB");
                        if let Ok(usb_entries) = strata_fs::read_dir(&enum_path) {
                            for usb_entry in usb_entries.flatten() {
                                if let Ok(device) = parse_usb_device(&usb_entry.path()) {
                                    devices.push(device);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(UsbHistory { devices })
}

fn parse_usb_device(device_path: &Path) -> Result<UsbDevice, ForensicError> {
    let mut vendor_id = String::new();
    let mut product_id = String::new();
    let mut serial_number = None;
    let mut friendly_name = None;
    let mut first_install_date = None;

    if let Ok(entries) = strata_fs::read_dir(device_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy();
                    let parts: Vec<&str> = name_str.split('&').collect();
                    if parts.len() >= 2 {
                        vendor_id = parts[0].to_string();
                        product_id = parts[1].to_string();
                    }
                    serial_number = Some(name_str.to_string());
                }

                if let Ok(props_path) = strata_fs::read_dir(&path) {
                    for prop_entry in props_path.flatten() {
                        let prop_path = prop_entry.path();
                        if let Ok(data) = super::scalpel::read_prefix(
                            &prop_path,
                            super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                        ) {
                            let prop_name = prop_path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default();

                            if prop_name.contains("FriendlyName") {
                                friendly_name =
                                    String::from_utf8(data.get(2..).unwrap_or(&data).to_vec())
                                        .ok()
                                        .map(|s| s.trim_end_matches('\0').to_string());
                            } else if prop_name.contains("InstallDate") && data.len() >= 4 {
                                first_install_date =
                                    Some(i32::from_le_bytes([data[0], data[1], data[2], data[3]])
                                        as i64);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(UsbDevice {
        vendor_id,
        product_id,
        serial_number,
        friendly_name,
        first_install_date,
        last_connected: first_install_date,
    })
}

pub fn get_usb_vendor_name(vid: &str) -> &'static str {
    match vid.to_uppercase().as_str() {
        "0403" => "FTDI",
        "0781" => "SanDisk",
        "0951" => "Kingston",
        "13FE" => "Transcend",
        "1F75" => "Innostor",
        "1058" => "Western Digital",
        "0BC2" => "Seagate",
        "04E8" => "Samsung",
        "0BDA" => "Realtek",
        "8087" => "Intel",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_usb_input_shape_supports_directory_json_csv() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("usb");
        let json = temp.path().join("usb.json");
        let csv = temp.path().join("usb.csv");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(
            &json,
            r#"[{"vendor_id":"0781","product_id":"5581","serial_number":"ABC","last_connected_unix":1700055001}]"#,
        )
        .expect("json");
        std::fs::write(
            &csv,
            "vendor_id,product_id,serial_number,last_connected_unix\n0781,5581,DEF,1700055002\n",
        )
        .expect("csv");

        assert_eq!(detect_usb_input_shape(&dir), UsbInputShape::Directory);
        assert_eq!(detect_usb_input_shape(&json), UsbInputShape::JsonArray);
        assert_eq!(detect_usb_input_shape(&csv), UsbInputShape::CsvText);
    }

    #[test]
    fn parse_usb_records_from_path_parses_json_rows() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("usb.json");
        std::fs::write(
            &path,
            r#"[{"vendor_id":"vid_0781","product_id":"pid_5581","serial_number":"ABC123","friendly_name":"SanDisk USB","last_connected_unix":1700055003,"user_sid":"s-1-5-21"}]"#,
        )
        .expect("write");

        let rows = parse_usb_records_from_path(&path, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].vendor_id.as_deref(), Some("0781"));
        assert_eq!(rows[0].product_id.as_deref(), Some("5581"));
        assert_eq!(rows[0].serial_number.as_deref(), Some("ABC123"));
        assert_eq!(rows[0].timestamp_unix, Some(1_700_055_003));
        assert_eq!(rows[0].user_sid.as_deref(), Some("S-1-5-21"));
    }

    #[test]
    fn parse_usb_text_fallback_handles_partial_rows() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("usb.txt");
        std::fs::write(&path, "0781:5581|ABC123\n0951:1666|XYZ987\n").expect("write");

        let rows = parse_usb_text_fallback(&path);
        assert!(rows.len() >= 2);
        assert!(rows
            .iter()
            .any(|r| r.serial_number.as_deref() == Some("ABC123")));
    }
}

use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WmiInputShape {
    Missing,
    Directory,
    Binary,
    JsonObject,
    JsonArray,
    Csv,
    LineText,
    Unknown,
}

impl WmiInputShape {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Directory => "directory",
            Self::Binary => "binary",
            Self::JsonObject => "json_object",
            Self::JsonArray => "json_array",
            Self::Csv => "csv",
            Self::LineText => "line_text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_wmi_input_shape(path: &Path) -> WmiInputShape {
    if !path.exists() {
        return WmiInputShape::Missing;
    }
    if path.is_dir() {
        return WmiInputShape::Directory;
    }
    let Ok(raw) = std::fs::read(path) else {
        return WmiInputShape::Missing;
    };
    if raw.is_empty() {
        return WmiInputShape::Unknown;
    }
    if raw
        .iter()
        .take(1024)
        .any(|b| *b == 0 && *b != b'\n' && *b != b'\r' && *b != b'\t')
    {
        return WmiInputShape::Binary;
    }
    let text = String::from_utf8_lossy(&raw);
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        return WmiInputShape::JsonObject;
    }
    if trimmed.starts_with('[') {
        return WmiInputShape::JsonArray;
    }
    if let Some(first_line) = trimmed.lines().next() {
        if first_line.contains(',') {
            return WmiInputShape::Csv;
        }
    }
    if !trimmed.is_empty() {
        return WmiInputShape::LineText;
    }
    WmiInputShape::Unknown
}

#[derive(Debug, Clone, Default)]
pub struct WmiDatabase {
    pub path: String,
    pub objects: Vec<WmiObject>,
    pub namespaces: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WmiObject {
    pub class_name: String,
    pub properties: HashMap<String, WmiProperty>,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct WmiProperty {
    pub name: String,
    pub value_type: WmiValueType,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub enum WmiValueType {
    #[default]
    String,
    Uint32,
    Uint64,
    Int32,
    Int64,
    Boolean,
    DateTime,
    Array,
    Object,
    Null,
}

#[derive(Debug, Clone, Default)]
pub struct WmiQueryResult {
    pub namespace: String,
    pub class_name: String,
    pub instances: Vec<WmiObject>,
    pub query_time_ms: u64,
}

pub fn parse_wmi_repository(base_path: &Path) -> Result<WmiDatabase, ForensicError> {
    let mut db = WmiDatabase {
        path: base_path.to_string_lossy().to_string(),
        ..Default::default()
    };

    db.namespaces = vec![
        "root\\cimv2".to_string(),
        "root\\security".to_string(),
        "root\\default".to_string(),
        "root\\wmi".to_string(),
    ];

    Ok(db)
}

pub fn execute_wmi_query(
    _namespace: &str,
    _class_name: &str,
    _properties: &[&str],
) -> Result<WmiQueryResult, ForensicError> {
    Ok(WmiQueryResult {
        namespace: _namespace.to_string(),
        class_name: _class_name.to_string(),
        instances: vec![],
        query_time_ms: 0,
    })
}

pub fn get_wmi_computer_system_info() -> Result<HashMap<String, String>, ForensicError> {
    let mut info = HashMap::new();
    info.insert("Name".to_string(), "".to_string());
    info.insert("Domain".to_string(), "".to_string());
    info.insert("Manufacturer".to_string(), "".to_string());
    info.insert("Model".to_string(), "".to_string());
    info.insert("SystemType".to_string(), "".to_string());
    info.insert("TotalPhysicalMemory".to_string(), "".to_string());
    Ok(info)
}

pub fn get_wmi_os_info() -> Result<HashMap<String, String>, ForensicError> {
    let mut info = HashMap::new();
    info.insert("Caption".to_string(), "".to_string());
    info.insert("Version".to_string(), "".to_string());
    info.insert("BuildNumber".to_string(), "".to_string());
    info.insert("InstallDate".to_string(), "".to_string());
    info.insert("LastBootUpTime".to_string(), "".to_string());
    info.insert("OSArchitecture".to_string(), "".to_string());
    Ok(info)
}

pub fn get_wmi_disk_drives() -> Result<Vec<WmiObject>, ForensicError> {
    get_wmi_objects("FORENSIC_WMI_DISK_DRIVES", "wmi_disk_drives.json")
}

pub fn get_wmi_network_configs() -> Result<Vec<WmiObject>, ForensicError> {
    get_wmi_objects("FORENSIC_WMI_NETWORK_CONFIGS", "wmi_network_configs.json")
}

pub fn get_wmi_logical_disks() -> Result<Vec<WmiObject>, ForensicError> {
    get_wmi_objects("FORENSIC_WMI_LOGICAL_DISKS", "wmi_logical_disks.json")
}

pub fn get_wmi_processes() -> Result<Vec<WmiObject>, ForensicError> {
    get_wmi_objects("FORENSIC_WMI_PROCESSES", "wmi_processes.json")
}

pub fn get_wmi_services() -> Result<Vec<WmiObject>, ForensicError> {
    get_wmi_objects("FORENSIC_WMI_SERVICES", "wmi_services.json")
}

pub fn get_wmi_scheduled_tasks() -> Result<Vec<WmiObject>, ForensicError> {
    get_wmi_objects("FORENSIC_WMI_SCHEDULED_TASKS", "wmi_scheduled_tasks.json")
}

pub fn get_wmi_usb_devices() -> Result<Vec<WmiObject>, ForensicError> {
    get_wmi_objects("FORENSIC_WMI_USB_DEVICES", "wmi_usb_devices.json")
}

pub fn get_wmi_installed_software() -> Result<Vec<WmiObject>, ForensicError> {
    get_wmi_objects(
        "FORENSIC_WMI_INSTALLED_SOFTWARE",
        "wmi_installed_software.json",
    )
}

pub fn get_wmi_startup_commands() -> Result<Vec<WmiObject>, ForensicError> {
    get_wmi_objects("FORENSIC_WMI_STARTUP_COMMANDS", "wmi_startup_commands.json")
}

pub fn get_wmi_system_restore_points() -> Result<Vec<WmiObject>, ForensicError> {
    get_wmi_objects(
        "FORENSIC_WMI_SYSTEM_RESTORE_POINTS",
        "wmi_system_restore_points.json",
    )
}

pub fn scan_wmi_repository(base_path: &Path) -> Result<Vec<WmiDatabase>, ForensicError> {
    let mut databases = vec![];

    if base_path.exists() {
        let db = parse_wmi_repository(base_path)?;
        databases.push(db);
    }

    Ok(databases)
}

pub fn extract_wmi_timestamps(wmi_obj: &WmiObject) -> HashMap<String, u64> {
    let mut timestamps = HashMap::new();

    for (key, prop) in &wmi_obj.properties {
        if key.to_lowercase().contains("time") || key.to_lowercase().contains("date") {
            if let Ok(ts) = prop.value.parse::<u64>() {
                timestamps.insert(key.clone(), ts);
            }
        }
    }

    timestamps
}

fn get_wmi_objects(env_key: &str, file: &str) -> Result<Vec<WmiObject>, ForensicError> {
    let Some(items) = load(path(env_key, file)) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| parse_wmi_object(&v))
        .filter(|x| !x.class_name.is_empty() || !x.properties.is_empty())
        .collect())
}

fn parse_wmi_object(v: &Value) -> WmiObject {
    let properties = v
        .get("properties")
        .and_then(Value::as_object)
        .map(|obj| {
            obj.iter()
                .map(|(k, x)| (k.clone(), parse_wmi_property(k, x)))
                .collect::<HashMap<String, WmiProperty>>()
        })
        .unwrap_or_default();

    WmiObject {
        class_name: s(v, &["class_name", "class"]),
        properties,
        timestamp: opt_n(v, &["timestamp", "time"]),
    }
}

fn parse_wmi_property(name: &str, v: &Value) -> WmiProperty {
    if let Some(obj) = v.as_object() {
        let value_str = obj
            .get("value")
            .map(value_to_string)
            .unwrap_or_else(String::new);
        let value_type = obj
            .get("value_type")
            .and_then(Value::as_str)
            .map(value_type_from_str)
            .unwrap_or_else(|| infer_value_type(obj.get("value")));
        return WmiProperty {
            name: obj
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(name)
                .to_string(),
            value_type,
            value: value_str,
        };
    }

    WmiProperty {
        name: name.to_string(),
        value_type: infer_value_type(Some(v)),
        value: value_to_string(v),
    }
}

fn value_type_from_str(value: &str) -> WmiValueType {
    match value.to_ascii_lowercase().as_str() {
        "uint32" => WmiValueType::Uint32,
        "uint64" => WmiValueType::Uint64,
        "int32" => WmiValueType::Int32,
        "int64" => WmiValueType::Int64,
        "boolean" | "bool" => WmiValueType::Boolean,
        "datetime" | "date_time" => WmiValueType::DateTime,
        "array" => WmiValueType::Array,
        "object" => WmiValueType::Object,
        "null" => WmiValueType::Null,
        _ => WmiValueType::String,
    }
}

fn infer_value_type(value: Option<&Value>) -> WmiValueType {
    match value {
        Some(Value::Null) => WmiValueType::Null,
        Some(Value::Bool(_)) => WmiValueType::Boolean,
        Some(Value::Number(n)) => {
            if n.as_u64().is_some() {
                WmiValueType::Uint64
            } else {
                WmiValueType::Int64
            }
        }
        Some(Value::Array(_)) => WmiValueType::Array,
        Some(Value::Object(_)) => WmiValueType::Object,
        Some(Value::String(s)) => {
            if s.contains('T') && s.contains(':') {
                WmiValueType::DateTime
            } else {
                WmiValueType::String
            }
        }
        None => WmiValueType::String,
    }
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("wmi").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let v: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = v.as_array() {
        Some(items.clone())
    } else if v.is_object() {
        v.get("instances")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| v.get("items").and_then(Value::as_array).cloned())
            .or_else(|| Some(vec![v]))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_wmi_input_shape_json_and_csv() {
        let dir = tempfile::tempdir().unwrap();
        let json = dir.path().join("wmi.json");
        let csv = dir.path().join("wmi.csv");

        strata_fs::write(&json, r#"{"items":[{"class":"Win32_Process"}]}"#).unwrap();
        strata_fs::write(&csv, "class,name\nWin32_Process,cmd.exe\n").unwrap();

        assert_eq!(detect_wmi_input_shape(&json), WmiInputShape::JsonObject);
        assert_eq!(detect_wmi_input_shape(&csv), WmiInputShape::Csv);
        assert_eq!(WmiInputShape::JsonObject.as_str(), "json_object");
    }
}

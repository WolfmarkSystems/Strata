use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_hex_bytes, parse_reg_u32,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceDriverInputShape {
    Missing,
    Binary,
    RegExport,
    JsonObject,
    JsonArray,
    Csv,
    LineText,
    Unknown,
}

impl ServiceDriverInputShape {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Binary => "binary",
            Self::RegExport => "reg",
            Self::JsonObject => "json_object",
            Self::JsonArray => "json_array",
            Self::Csv => "csv",
            Self::LineText => "line_text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_services_drivers_input_shape(path: &Path) -> ServiceDriverInputShape {
    let Ok(raw) = std::fs::read(path) else {
        return ServiceDriverInputShape::Missing;
    };
    if raw.is_empty() {
        return ServiceDriverInputShape::Unknown;
    }
    if raw
        .iter()
        .take(1024)
        .any(|b| *b == 0 && *b != b'\n' && *b != b'\r' && *b != b'\t')
    {
        return ServiceDriverInputShape::Binary;
    }
    let text = String::from_utf8_lossy(&raw);
    let trimmed = text.trim_start();
    if trimmed.starts_with("Windows Registry Editor")
        || trimmed.starts_with("[HKEY_")
        || trimmed.starts_with("[-HKEY_")
    {
        return ServiceDriverInputShape::RegExport;
    }
    if trimmed.starts_with('{') {
        return ServiceDriverInputShape::JsonObject;
    }
    if trimmed.starts_with('[') {
        return ServiceDriverInputShape::JsonArray;
    }
    if let Some(first_line) = trimmed.lines().next() {
        if first_line.contains(',') {
            return ServiceDriverInputShape::Csv;
        }
    }
    if !trimmed.is_empty() {
        return ServiceDriverInputShape::LineText;
    }
    ServiceDriverInputShape::Unknown
}

pub fn get_services_config() -> Vec<ServiceConfig> {
    get_services_config_from_reg(&default_reg_path("services.reg"))
}

pub fn get_services_config_from_reg(path: &Path) -> Vec<ServiceConfig> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| is_service_root_record(&r.path)) {
        let Some(name) = extract_service_name(&record.path) else {
            continue;
        };
        let start_type = record
            .values
            .get("Start")
            .and_then(|v| parse_start_type(v))
            .unwrap_or("Unknown")
            .to_string();
        let service_type = record
            .values
            .get("Type")
            .map(|v| format_service_type(v))
            .unwrap_or_else(|| "Unknown".to_string());

        out.push(ServiceConfig {
            name: name.clone(),
            display_name: record
                .values
                .get("DisplayName")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| name.clone()),
            start_type,
            path: record
                .values
                .get("ImagePath")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            service_type,
            service_account: record
                .values
                .get("ObjectName")
                .and_then(|v| decode_reg_string(v))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            description: record
                .values
                .get("Description")
                .and_then(|v| decode_reg_string(v)),
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct ServiceConfig {
    pub name: String,
    pub display_name: String,
    pub start_type: String,
    pub path: String,
    pub service_type: String,
    pub service_account: Option<String>,
    pub description: Option<String>,
}

pub fn get_service_failure() -> Vec<ServiceFailure> {
    get_service_failure_from_reg(&default_reg_path("services.reg"))
}

pub fn get_service_failure_from_reg(path: &Path) -> Vec<ServiceFailure> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| is_service_root_record(&r.path)) {
        let Some(service_name) = extract_service_name(&record.path) else {
            continue;
        };
        let mut reset_period = record
            .values
            .get("FailureActionsOnNonCrashFailures")
            .and_then(|v| parse_reg_u32(v))
            .unwrap_or(0);
        let mut actions = Vec::new();

        if let Some(raw) = record.values.get("FailureActions") {
            if let Some(bytes) = parse_hex_bytes(raw) {
                if let Some(decoded) = parse_failure_actions_blob(&bytes) {
                    if reset_period == 0 {
                        if let Some(period) = decoded.reset_period {
                            reset_period = period;
                        }
                    }
                    actions.extend(decoded.actions);
                } else if !bytes.is_empty() {
                    actions.push(format!("raw_bytes={}", bytes.len()));
                }
            }
        }

        if reset_period > 0 || !actions.is_empty() {
            out.push(ServiceFailure {
                service: service_name,
                reset_period,
                actions,
            });
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
struct FailureActionsDecoded {
    reset_period: Option<u32>,
    actions: Vec<String>,
}

fn parse_failure_actions_blob(bytes: &[u8]) -> Option<FailureActionsDecoded> {
    if bytes.len() < 8 {
        return None;
    }
    let mut best: Option<FailureActionsDecoded> = None;
    // Common SERVICE_FAILURE_ACTIONS layouts from serialized registry values.
    let layouts: &[(usize, usize)] = &[(12, 20), (12, 24), (20, 28), (24, 32), (24, 40)];

    for (count_off, actions_off) in layouts {
        let Some(action_count) = le_u32_at(bytes, *count_off) else {
            continue;
        };
        if action_count == 0 || action_count > 64 {
            continue;
        }
        let action_count = action_count as usize;
        let needed = actions_off.saturating_add(action_count.saturating_mul(8));
        if needed > bytes.len() {
            continue;
        }

        let mut parsed_actions = Vec::new();
        let mut all_known = true;
        for idx in 0..action_count {
            let off = actions_off + (idx * 8);
            let Some(action_type) = le_u32_at(bytes, off) else {
                all_known = false;
                break;
            };
            let Some(delay_ms) = le_u32_at(bytes, off + 4) else {
                all_known = false;
                break;
            };
            if let Some(label) = map_failure_action_type(action_type) {
                parsed_actions.push(format!("{}({}ms)", label, delay_ms));
            } else {
                all_known = false;
                parsed_actions.push(format!("type_{}({}ms)", action_type, delay_ms));
            }
        }
        if parsed_actions.is_empty() {
            continue;
        }

        let candidate = FailureActionsDecoded {
            reset_period: le_u32_at(bytes, 0),
            actions: parsed_actions,
        };

        match &best {
            None => best = Some(candidate),
            Some(current) => {
                if candidate.actions.len() > current.actions.len()
                    || (candidate.actions.len() == current.actions.len() && all_known)
                {
                    best = Some(candidate);
                }
            }
        }
    }

    best
}

fn map_failure_action_type(value: u32) -> Option<&'static str> {
    match value {
        0 => Some("none"),
        1 => Some("restart"),
        2 => Some("reboot"),
        3 => Some("run-command"),
        _ => None,
    }
}

fn le_u32_at(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

#[derive(Debug, Clone, Default)]
pub struct ServiceFailure {
    pub service: String,
    pub reset_period: u32,
    pub actions: Vec<String>,
}

pub fn get_delayed_services() -> Vec<DelayedService> {
    get_delayed_services_from_reg(&default_reg_path("services.reg"))
}

pub fn get_delayed_services_from_reg(path: &Path) -> Vec<DelayedService> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| is_service_root_record(&r.path)) {
        let delayed = record
            .values
            .get("DelayedAutoStart")
            .and_then(|v| parse_reg_u32(v))
            .unwrap_or(0)
            != 0;

        if delayed {
            out.push(DelayedService {
                name: extract_service_name(&record.path).unwrap_or_else(|| key_leaf(&record.path)),
                delayed_start: true,
            });
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct DelayedService {
    pub name: String,
    pub delayed_start: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ServiceDllEntry {
    pub service: String,
    pub dll_path: String,
    pub service_main: Option<String>,
    pub host_image_path: Option<String>,
    pub suspicious: bool,
    pub reasons: Vec<String>,
}

pub fn get_service_dll_entries_from_reg(path: &Path) -> Vec<ServiceDllEntry> {
    let records = load_reg_records(path);
    let mut root_image_paths = std::collections::BTreeMap::<String, String>::new();
    for record in records.iter().filter(|r| is_service_root_record(&r.path)) {
        if let Some(name) = extract_service_name(&record.path) {
            if let Some(image) = record
                .values
                .get("ImagePath")
                .and_then(|v| decode_reg_string(v))
            {
                if !image.trim().is_empty() {
                    root_image_paths.insert(name, image);
                }
            }
        }
    }

    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| is_service_parameters_record(&r.path))
    {
        let Some(service_name) = extract_service_name(&record.path) else {
            continue;
        };
        let Some(dll_path) = record
            .values
            .get("ServiceDll")
            .and_then(|v| decode_reg_string(v))
            .filter(|v| !v.trim().is_empty())
        else {
            continue;
        };

        let service_main = record
            .values
            .get("ServiceMain")
            .and_then(|v| decode_reg_string(v));
        let host_image_path = root_image_paths.get(&service_name).cloned();
        let mut reasons = Vec::new();

        if !is_system32_path(&dll_path) {
            reasons.push("dll_outside_system32".to_string());
        }
        if let Some(host) = host_image_path.as_deref() {
            if !host.to_ascii_lowercase().contains("svchost.exe") {
                reasons.push("service_host_not_svchost".to_string());
            }
        }
        if service_main
            .as_deref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
            && !service_main
                .as_deref()
                .unwrap_or_default()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            reasons.push("service_main_non_alnum".to_string());
        }

        out.push(ServiceDllEntry {
            service: service_name,
            dll_path,
            service_main,
            host_image_path,
            suspicious: !reasons.is_empty(),
            reasons,
        });
    }

    out.sort_by(|a, b| {
        a.service
            .cmp(&b.service)
            .then_with(|| a.dll_path.cmp(&b.dll_path))
    });
    out
}

fn is_service_root_record(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let marker = "\\currentcontrolset\\services\\";
    let Some(start) = lower.find(marker) else {
        return false;
    };
    let suffix = &path[start + marker.len()..];
    !suffix.is_empty() && !suffix.contains('\\')
}

fn extract_service_name(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let marker = "\\currentcontrolset\\services\\";
    let start = lower.find(marker)?;
    let suffix = &path[start + marker.len()..];
    let name = suffix.split('\\').next()?.trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn is_service_parameters_record(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let marker = "\\currentcontrolset\\services\\";
    let Some(start) = lower.find(marker) else {
        return false;
    };
    let suffix = &lower[start + marker.len()..];
    suffix.ends_with("\\parameters")
}

fn is_system32_path(path: &str) -> bool {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();
    normalized.starts_with(r"c:\windows\system32\")
        || normalized.starts_with(r"%systemroot%\system32\")
        || normalized.starts_with(r"\systemroot\system32\")
}

fn parse_start_type(raw: &str) -> Option<&'static str> {
    if let Some(value) = parse_reg_u32(raw) {
        return Some(match value {
            0 => "Boot",
            1 => "System",
            2 => "Automatic",
            3 => "Manual",
            4 => "Disabled",
            _ => "Unknown",
        });
    }
    let decoded = decode_reg_string(raw)?;
    let lower = decoded.trim().to_ascii_lowercase();
    if lower.contains("auto") {
        Some("Automatic")
    } else if lower.contains("boot") {
        Some("Boot")
    } else if lower.contains("system") {
        Some("System")
    } else if lower.contains("manual") || lower.contains("demand") {
        Some("Manual")
    } else if lower.contains("disabled") {
        Some("Disabled")
    } else {
        Some("Unknown")
    }
}

fn format_service_type(raw: &str) -> String {
    let Some(value) = parse_reg_u32(raw) else {
        return decode_reg_string(raw)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "Unknown".to_string());
    };
    let mut tags = Vec::new();
    if (value & 0x0000_0001) != 0 {
        tags.push("KernelDriver");
    }
    if (value & 0x0000_0002) != 0 {
        tags.push("FileSystemDriver");
    }
    if (value & 0x0000_0004) != 0 {
        tags.push("Adapter");
    }
    if (value & 0x0000_0008) != 0 {
        tags.push("RecognizerDriver");
    }
    if (value & 0x0000_0010) != 0 {
        tags.push("Win32OwnProcess");
    }
    if (value & 0x0000_0020) != 0 {
        tags.push("Win32ShareProcess");
    }
    if (value & 0x0000_0100) != 0 {
        tags.push("InteractiveProcess");
    }
    if tags.is_empty() {
        "Unknown".to_string()
    } else {
        tags.join("|")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_service_config() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("services.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ExampleSvc]
"DisplayName"="Example Service"
"ImagePath"="C:\Program Files\Example\svc.exe"
"Start"=dword:00000002
"Type"=dword:00000010
"ObjectName"="LocalSystem"
"DelayedAutoStart"=dword:00000001
"#,
        )
        .unwrap();

        let rows = get_services_config_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "ExampleSvc");
        assert_eq!(rows[0].start_type, "Automatic");
        assert_eq!(rows[0].service_type, "Win32OwnProcess");
        assert_eq!(rows[0].service_account.as_deref(), Some("LocalSystem"));
        assert_eq!(get_delayed_services_from_reg(&file).len(), 1);
    }

    #[test]
    fn parse_service_config_ignores_nested_subkeys() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("services.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RootSvc]
"DisplayName"="Root Service"
"Start"=dword:00000003
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RootSvc\Parameters]
"DisplayName"="Nested Should Not Be Parsed"
"Start"=dword:00000004
"#,
        )
        .unwrap();

        let rows = get_services_config_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "RootSvc");
        assert_eq!(rows[0].display_name, "Root Service");
        assert_eq!(rows[0].service_type, "Unknown");
        assert_eq!(rows[0].service_account, None);
    }

    #[test]
    fn parse_service_config_start_aliases_and_service_type_flags() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("services.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AliasSvc]
"DisplayName"="Alias Service"
"ImagePath"="C:\Windows\System32\svchost.exe -k LocalService"
"Start"="Auto Start"
"Type"=dword:00000110
"ObjectName"="NT AUTHORITY\LocalService"
"#,
        )
        .unwrap();

        let rows = get_services_config_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].start_type, "Automatic");
        assert_eq!(rows[0].service_type, "Win32OwnProcess|InteractiveProcess");
        assert_eq!(
            rows[0].service_account.as_deref(),
            Some("NT AUTHORITY\\LocalService")
        );
    }

    #[test]
    fn parse_service_dll_entries_and_flag_suspicious() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("services.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LegitSvc]
"ImagePath"="%SystemRoot%\System32\svchost.exe -k netsvcs"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LegitSvc\Parameters]
"ServiceDll"="%SystemRoot%\System32\legit.dll"
"ServiceMain"="ServiceMain"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BadSvc]
"ImagePath"="C:\Program Files\Bad\badhost.exe"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BadSvc\Parameters]
"ServiceDll"="C:\Users\Public\bad.dll"
"ServiceMain"="Run-Now"
"#,
        )
        .unwrap();

        let rows = get_service_dll_entries_from_reg(&file);
        assert_eq!(rows.len(), 2);

        let legit = rows.iter().find(|r| r.service == "LegitSvc").unwrap();
        assert!(!legit.suspicious);

        let bad = rows.iter().find(|r| r.service == "BadSvc").unwrap();
        assert!(bad.suspicious);
        assert!(bad.reasons.iter().any(|r| r == "dll_outside_system32"));
        assert!(bad.reasons.iter().any(|r| r == "service_host_not_svchost"));
        assert!(bad.reasons.iter().any(|r| r == "service_main_non_alnum"));
    }

    #[test]
    fn detect_services_drivers_shape_reg_json_csv() {
        let dir = tempfile::tempdir().unwrap();
        let reg = dir.path().join("services.reg");
        let json = dir.path().join("services.json");
        let csv = dir.path().join("services.csv");

        strata_fs::write(
            &reg,
            "Windows Registry Editor Version 5.00\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TestSvc]\n",
        )
        .unwrap();
        strata_fs::write(&json, r#"{"records":[{"service":"TestSvc"}]}"#).unwrap();
        strata_fs::write(
            &csv,
            "service,image_path\nTestSvc,C:\\Windows\\System32\\svchost.exe\n",
        )
        .unwrap();

        assert_eq!(
            detect_services_drivers_input_shape(&reg),
            ServiceDriverInputShape::RegExport
        );
        assert_eq!(
            detect_services_drivers_input_shape(&json),
            ServiceDriverInputShape::JsonObject
        );
        assert_eq!(
            detect_services_drivers_input_shape(&csv),
            ServiceDriverInputShape::Csv
        );
        assert_eq!(
            ServiceDriverInputShape::RegExport.as_str(),
            "reg",
            "as_str contract should remain stable"
        );
    }

    #[test]
    fn parse_service_failure_decodes_structured_actions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("services.reg");

        // 32-bit SERVICE_FAILURE_ACTIONS-style bytes:
        // reset=86400, cActions=2, actions=[restart 60000ms, run-command 0ms]
        let failure_actions = "hex:80,51,01,00,00,00,00,00,00,00,00,00,02,00,00,00,14,00,00,00,01,00,00,00,60,ea,00,00,03,00,00,00,00,00,00,00";
        strata_fs::write(
            &file,
            format!(
                r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ActionSvc]
"FailureActions"={}
"FailureActionsOnNonCrashFailures"=dword:00000000
"#,
                failure_actions
            ),
        )
        .unwrap();

        let rows = get_service_failure_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].service, "ActionSvc");
        assert_eq!(rows[0].reset_period, 86_400);
        assert!(rows[0].actions.iter().any(|a| a == "restart(60000ms)"));
        assert!(rows[0].actions.iter().any(|a| a == "run-command(0ms)"));
    }

    #[test]
    fn parse_service_failure_falls_back_to_raw_blob_length() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("services.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RawSvc]
"FailureActions"=hex:aa,bb,cc,dd
"FailureActionsOnNonCrashFailures"=dword:00000001
"#,
        )
        .unwrap();

        let rows = get_service_failure_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].service, "RawSvc");
        assert_eq!(rows[0].reset_period, 1);
        assert!(rows[0].actions.iter().any(|a| a == "raw_bytes=4"));
    }
}

use std::collections::BTreeMap;
use std::path::Path;

use super::reg_export::default_reg_path;
use super::regservice;

pub fn get_windows_services() -> Vec<WindowsService> {
    get_windows_services_from_reg(&default_reg_path("services.reg"))
}

pub fn get_windows_services_from_reg(path: &Path) -> Vec<WindowsService> {
    let service_rows = regservice::get_services_config_from_reg(path);
    let dll_rows = regservice::get_service_dll_entries_from_reg(path);

    let mut dll_reason_map = BTreeMap::<String, Vec<String>>::new();
    for dll in dll_rows {
        if dll.suspicious {
            dll_reason_map
                .entry(dll.service)
                .or_default()
                .extend(dll.reasons);
        }
    }

    let mut out = service_rows
        .into_iter()
        .map(|service| {
            let auto_start = matches!(
                service.start_type.as_str(),
                "Automatic" | "Boot" | "System"
            );
            let kernel_driver = service.service_type.contains("KernelDriver")
                || service.service_type.contains("FileSystemDriver");

            let mut reasons = Vec::new();
            if !service.path.trim().is_empty() && !is_standard_service_path(&service.path) {
                reasons.push("binary_outside_system_paths".to_string());
            }
            if auto_start && !service.path.trim().is_empty() && !is_standard_service_path(&service.path)
            {
                reasons.push("autostart_non_system_binary".to_string());
            }
            if kernel_driver {
                reasons.push("kernel_or_fs_driver".to_string());
            }
            if let Some(account) = service.service_account.as_deref() {
                if !is_standard_service_account(account) {
                    reasons.push("non_standard_service_account".to_string());
                }
            }
            if let Some(extra) = dll_reason_map.get(&service.name) {
                reasons.extend(extra.clone());
            }

            reasons.sort();
            reasons.dedup();

            WindowsService {
                name: service.name,
                status: service.start_type.clone(),
                display_name: service.display_name,
                start_type: service.start_type,
                image_path: service.path,
                service_type: service.service_type,
                service_account: service.service_account,
                description: service.description,
                auto_start,
                kernel_driver,
                suspicious: !reasons.is_empty(),
                reasons,
            }
        })
        .collect::<Vec<_>>();

    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[derive(Debug, Clone, Default)]
pub struct WindowsService {
    pub name: String,
    pub status: String,
    pub display_name: String,
    pub start_type: String,
    pub image_path: String,
    pub service_type: String,
    pub service_account: Option<String>,
    pub description: Option<String>,
    pub auto_start: bool,
    pub kernel_driver: bool,
    pub suspicious: bool,
    pub reasons: Vec<String>,
}

fn is_standard_service_path(path: &str) -> bool {
    let normalized = path
        .trim_matches('"')
        .replace('/', "\\")
        .replace("\\??\\", "")
        .to_ascii_lowercase();

    normalized.starts_with("c:\\windows\\system32\\")
        || normalized.starts_with("%systemroot%\\system32\\")
        || normalized.starts_with("\\systemroot\\system32\\")
}

fn is_standard_service_account(account: &str) -> bool {
    let lower = account.trim().to_ascii_lowercase();
    lower == "localsystem"
        || lower == "localservice"
        || lower == "networkservice"
        || lower.starts_with("nt authority\\")
        || lower.starts_with("local system")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_windows_services_flags_suspicious_entries() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("services.reg");

        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LegitSvc]
"DisplayName"="Legit Service"
"ImagePath"="%SystemRoot%\\System32\\svchost.exe -k netsvcs"
"Start"=dword:00000002
"Type"=dword:00000020
"ObjectName"="NT AUTHORITY\\LocalService"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EvilSvc]
"DisplayName"="Evil Service"
"ImagePath"="C:\\Users\\Public\\evil.exe"
"Start"=dword:00000002
"Type"=dword:00000010
"ObjectName"="DOMAIN\\svc_backdoor"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EvilSvc\Parameters]
"ServiceDll"="C:\\Users\\Public\\evil.dll"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DriverSvc]
"DisplayName"="Driver Service"
"ImagePath"="C:\\Windows\\System32\\drivers\\drv.sys"
"Start"=dword:00000001
"Type"=dword:00000001
"ObjectName"="LocalSystem"
"#,
        )
        .expect("write reg");

        let services = get_windows_services_from_reg(&file);
        assert_eq!(services.len(), 3);

        let legit = services.iter().find(|s| s.name == "LegitSvc").expect("legit");
        assert!(
            !legit.suspicious,
            "legit service unexpectedly suspicious: reasons={:?}, image_path={}",
            legit.reasons,
            legit.image_path
        );
        assert!(legit.auto_start);

        let evil = services.iter().find(|s| s.name == "EvilSvc").expect("evil");
        assert!(evil.suspicious);
        assert!(evil
            .reasons
            .iter()
            .any(|r| r == "binary_outside_system_paths"));
        assert!(evil
            .reasons
            .iter()
            .any(|r| r == "non_standard_service_account"));
        assert!(
            evil.reasons.iter().any(|r| r == "dll_outside_system32"),
            "reasons={:?}",
            evil.reasons
        );

        let driver = services
            .iter()
            .find(|s| s.name == "DriverSvc")
            .expect("driver");
        assert!(driver.kernel_driver);
        assert!(driver.reasons.iter().any(|r| r == "kernel_or_fs_driver"));
    }

    #[test]
    fn parse_windows_services_returns_empty_for_missing_input() {
        let rows = get_windows_services_from_reg(Path::new("does_not_exist.reg"));
        assert!(rows.is_empty());
    }
}

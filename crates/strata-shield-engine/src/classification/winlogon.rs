use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32, parse_reg_u64,
};
use super::reglogon;
use crate::errors::ForensicError;

pub fn get_winlogon_info() -> Result<WinlogonInfo, ForensicError> {
    get_winlogon_info_from_reg(&default_reg_path("logon.reg"))
}

pub fn get_winlogon_info_from_reg(path: &Path) -> Result<WinlogonInfo, ForensicError> {
    let raw = reglogon::get_winlogon_info_from_reg(path);
    let anomalies = reglogon::get_winlogon_anomalies_from_reg(path);
    let records = load_reg_records(path);

    let root = records.iter().find(|record| {
        let lower = record.path.to_ascii_lowercase();
        lower.contains("\\windows nt\\currentversion\\winlogon") && !lower.contains("\\notify\\")
    });

    let default_user_name = root.and_then(|record| {
        record
            .values
            .get("DefaultUserName")
            .and_then(|value| decode_reg_string(value))
            .or_else(|| {
                record
                    .values
                    .get("LastUsedUsername")
                    .and_then(|value| decode_reg_string(value))
            })
    });

    let auto_admin_logon = root
        .and_then(|record| record.values.get("AutoAdminLogon"))
        .map(|value| parse_auto_admin(value))
        .unwrap_or(false);

    let logon_time = root
        .and_then(|record| record.values.get("LastLogonTimestamp"))
        .and_then(|value| parse_reg_u64(value))
        .unwrap_or(0);

    let notify_packages = records
        .iter()
        .filter(|record| {
            record
                .path
                .to_ascii_lowercase()
                .contains("\\windows nt\\currentversion\\winlogon\\notify\\")
        })
        .map(|record| {
            let package = key_leaf(&record.path);
            if let Some(dll) = record
                .values
                .get("DLLName")
                .and_then(|value| decode_reg_string(value))
            {
                format!("{} ({})", package, dll)
            } else {
                package
            }
        })
        .collect::<Vec<_>>();

    let mut alerts = anomalies
        .iter()
        .map(|a| format!("{}:{} [{}]", a.value_name, a.reason, a.severity))
        .collect::<Vec<_>>();

    if auto_admin_logon {
        alerts.push("AutoAdminLogon enabled".to_string());
    }
    if !notify_packages.is_empty() {
        alerts.push(format!("Winlogon notify packages: {}", notify_packages.len()));
    }

    Ok(WinlogonInfo {
        last_user: default_user_name
            .clone()
            .or_else(|| {
                if raw.userinit.trim().is_empty() {
                    None
                } else {
                    Some(raw.userinit.clone())
                }
            })
            .unwrap_or_default(),
        logon_time,
        shell: raw.shell,
        userinit: raw.userinit,
        auto_admin_logon,
        default_user_name,
        notify_packages,
        suspicious: !alerts.is_empty(),
        alerts,
    })
}

#[derive(Debug, Clone, Default)]
pub struct WinlogonInfo {
    pub last_user: String,
    pub logon_time: u64,
    pub shell: String,
    pub userinit: String,
    pub auto_admin_logon: bool,
    pub default_user_name: Option<String>,
    pub notify_packages: Vec<String>,
    pub suspicious: bool,
    pub alerts: Vec<String>,
}

fn parse_auto_admin(value: &str) -> bool {
    if let Some(raw) = parse_reg_u32(value) {
        return raw != 0;
    }

    decode_reg_string(value)
        .map(|decoded| {
            let lower = decoded.trim().to_ascii_lowercase();
            matches!(lower.as_str(), "1" | "true" | "yes" | "enabled")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_winlogon_info_with_alerts_and_notify_packages() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("logon.reg");

        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"Shell"="explorer.exe,evil.exe"
"Userinit"="C:\\Windows\\system32\\userinit.exe,C:\\Temp\\evil.exe"
"AutoAdminLogon"="1"
"DefaultUserName"="ForensicAnalyst"
"LastLogonTimestamp"=qword:0000000065f6f900

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\BadPkg]
"DLLName"="C:\\Users\\Public\\badpkg.dll"
"#,
        )
        .expect("write reg");

        let info = get_winlogon_info_from_reg(&file).expect("winlogon info");
        assert_eq!(info.last_user, "ForensicAnalyst");
        assert!(info.auto_admin_logon);
        assert!(info
            .notify_packages
            .iter()
            .any(|item| item.contains("BadPkg")));
        assert!(info.suspicious);
        assert!(info.alerts.iter().any(|a| a.contains("AutoAdminLogon")));
        assert!(info.alerts.iter().any(|a| a.contains("multiple_shell_entries")));
    }

    #[test]
    fn parse_winlogon_info_benign_configuration() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("logon.reg");

        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"Shell"="explorer.exe"
"Userinit"="C:\\Windows\\system32\\userinit.exe,"
"AutoAdminLogon"="0"
"DefaultUserName"="Examiner"
"#,
        )
        .expect("write reg");

        let info = get_winlogon_info_from_reg(&file).expect("winlogon info");
        assert_eq!(info.last_user, "Examiner");
        assert!(!info.auto_admin_logon);
        assert!(!info.suspicious);
        assert!(info.alerts.is_empty());
    }
}

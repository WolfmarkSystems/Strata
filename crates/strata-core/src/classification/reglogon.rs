use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32,
};

pub fn get_winlogon_info() -> WinlogonInfo {
    get_winlogon_info_from_reg(&default_reg_path("logon.reg"))
}

pub fn get_winlogon_info_from_reg(path: &Path) -> WinlogonInfo {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\windows nt\\currentversion\\winlogon")
    }) {
        WinlogonInfo {
            shell: record
                .values
                .get("Shell")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| "explorer.exe".to_string()),
            userinit: record
                .values
                .get("Userinit")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            logon_screensaver: record
                .values
                .get("ScreenSaverIsSecure")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
        }
    } else {
        WinlogonInfo::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct WinlogonInfo {
    pub shell: String,
    pub userinit: String,
    pub logon_screensaver: bool,
}

pub fn get_gina_dll() -> Option<String> {
    get_gina_dll_from_reg(&default_reg_path("logon.reg"))
}

pub fn get_gina_dll_from_reg(path: &Path) -> Option<String> {
    let records = load_reg_records(path);
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\windows nt\\currentversion\\winlogon")
    }) {
        if let Some(v) = record.values.get("GinaDLL") {
            return decode_reg_string(v);
        }
    }
    None
}

pub fn get_credential_provider() -> Vec<CredProvider> {
    get_credential_provider_from_reg(&default_reg_path("logon.reg"))
}

pub fn get_credential_provider_from_reg(path: &Path) -> Vec<CredProvider> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\authentication\\credential providers\\")
    }) {
        out.push(CredProvider {
            clsid: key_leaf(&record.path),
            name: record
                .values
                .get("@")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct CredProvider {
    pub clsid: String,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct WinlogonAnomaly {
    pub path: String,
    pub value_name: String,
    pub value: String,
    pub reason: String,
    pub severity: String,
}

pub fn get_winlogon_anomalies_from_reg(path: &Path) -> Vec<WinlogonAnomaly> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\windows nt\\currentversion\\winlogon")
    }) {
        if let Some(shell) = record
            .values
            .get("Shell")
            .and_then(|v| decode_reg_string(v))
        {
            let shell_parts = split_csv_like(&shell);
            let has_explorer = shell_parts
                .iter()
                .any(|p| p.to_ascii_lowercase().contains("explorer.exe"));
            if !has_explorer {
                out.push(WinlogonAnomaly {
                    path: format!("{}\\Shell", record.path),
                    value_name: "Shell".to_string(),
                    value: shell.clone(),
                    reason: "custom_shell_missing_explorer".to_string(),
                    severity: "high".to_string(),
                });
            } else if shell_parts.len() > 1 {
                out.push(WinlogonAnomaly {
                    path: format!("{}\\Shell", record.path),
                    value_name: "Shell".to_string(),
                    value: shell.clone(),
                    reason: "multiple_shell_entries".to_string(),
                    severity: "medium".to_string(),
                });
            }
        }

        if let Some(userinit) = record
            .values
            .get("Userinit")
            .and_then(|v| decode_reg_string(v))
        {
            let userinit_parts = split_csv_like(&userinit);
            let has_userinit = userinit_parts
                .iter()
                .any(|p| p.to_ascii_lowercase().contains("userinit.exe"));
            if !has_userinit {
                out.push(WinlogonAnomaly {
                    path: format!("{}\\Userinit", record.path),
                    value_name: "Userinit".to_string(),
                    value: userinit.clone(),
                    reason: "userinit_missing_default_binary".to_string(),
                    severity: "high".to_string(),
                });
            } else if userinit_parts.len() > 1 {
                out.push(WinlogonAnomaly {
                    path: format!("{}\\Userinit", record.path),
                    value_name: "Userinit".to_string(),
                    value: userinit.clone(),
                    reason: "multiple_userinit_entries".to_string(),
                    severity: "high".to_string(),
                });
            }
        }

        for special in ["GinaDLL", "Taskman", "VmApplet"] {
            if let Some(value) = record
                .values
                .get(special)
                .and_then(|v| decode_reg_string(v))
            {
                if !value.trim().is_empty() {
                    out.push(WinlogonAnomaly {
                        path: format!("{}\\{}", record.path, special),
                        value_name: special.to_string(),
                        value,
                        reason: format!("winlogon_{}_override", special.to_ascii_lowercase()),
                        severity: "high".to_string(),
                    });
                }
            }
        }
    }

    out.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.reason.cmp(&b.reason))
            .then_with(|| a.value_name.cmp(&b.value_name))
    });
    out
}

fn split_csv_like(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|item| item.trim().trim_matches('"'))
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_winlogon_basics() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("logon.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"Shell"="explorer.exe"
"Userinit"="C:\Windows\system32\userinit.exe,"
"ScreenSaverIsSecure"=dword:00000001
"#,
        )
        .unwrap();
        let info = get_winlogon_info_from_reg(&file);
        assert_eq!(info.shell, "explorer.exe");
        assert!(info.logon_screensaver);
    }

    #[test]
    fn detect_winlogon_anomalies() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("logon.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"Shell"="explorer.exe, badshell.exe"
"Userinit"="C:\Windows\system32\userinit.exe,C:\Tools\evil.exe"
"GinaDLL"="evilgina.dll"
"#,
        )
        .unwrap();
        let rows = get_winlogon_anomalies_from_reg(&file);
        assert!(rows.iter().any(|r| r.reason == "multiple_shell_entries"));
        assert!(rows.iter().any(|r| r.reason == "multiple_userinit_entries"));
        assert!(rows.iter().any(|r| r.reason == "winlogon_ginadll_override"));
    }

    #[test]
    fn detect_winlogon_anomalies_empty_for_benign() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("logon.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"Shell"="explorer.exe"
"Userinit"="C:\Windows\system32\userinit.exe,"
"#,
        )
        .unwrap();
        let rows = get_winlogon_anomalies_from_reg(&file);
        assert!(rows.is_empty());
    }
}

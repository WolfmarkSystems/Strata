use std::path::{Path, PathBuf};

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records, parse_reg_u64};
use super::regwinver;

pub fn get_computer_info() -> ComputerInfo {
    get_computer_info_from_sources(&[
        default_reg_path("system.reg"),
        default_reg_path("winver.reg"),
        default_reg_path("network.reg"),
    ])
}

pub fn get_computer_info_from_sources(paths: &[PathBuf]) -> ComputerInfo {
    let mut info = ComputerInfo::default();

    for path in paths {
        apply_computer_info_from_reg(path.as_path(), &mut info);
    }

    let winver_path = paths
        .iter()
        .find(|p| p.to_string_lossy().to_ascii_lowercase().contains("winver"))
        .cloned()
        .unwrap_or_else(|| default_reg_path("winver.reg"));

    let version = regwinver::get_windows_version_from_reg(&winver_path);
    if version.major > 0 || version.build > 0 {
        info.os_version = if version.major > 0 {
            format!("{}.{}.{}", version.major, version.minor, version.build)
        } else {
            format!("build {}", version.build)
        };
    }

    info.install_date = regwinver::get_install_date_from_reg(&winver_path);
    info.system_root = regwinver::get_system_root_from_reg(&winver_path);

    if info.name.is_empty() {
        info.name = std::env::var("COMPUTERNAME").unwrap_or_default();
    }
    if info.domain.is_empty() {
        info.domain = std::env::var("USERDOMAIN").unwrap_or_default();
    }

    info
}

fn apply_computer_info_from_reg(path: &Path, info: &mut ComputerInfo) {
    let records = load_reg_records(path);
    for record in &records {
        let lower = record.path.to_ascii_lowercase();

        if info.name.is_empty()
            && lower.contains("\\control\\computername\\computername")
        {
            if let Some(value) = record
                .values
                .get("ComputerName")
                .and_then(|raw| decode_reg_string(raw))
                .filter(|value| !value.trim().is_empty())
            {
                info.name = value;
            }
        }

        if info.domain.is_empty()
            && lower.contains("\\services\\tcpip\\parameters")
        {
            if let Some(value) = record
                .values
                .get("Domain")
                .or_else(|| record.values.get("NV Domain"))
                .and_then(|raw| decode_reg_string(raw))
                .filter(|value| !value.trim().is_empty())
            {
                info.domain = value;
            }
        }

        if info.install_date.is_none()
            && lower.contains("microsoft\\windows nt\\currentversion")
        {
            info.install_date = record
                .values
                .get("InstallDate")
                .and_then(|raw| parse_reg_u64(raw));
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ComputerInfo {
    pub name: String,
    pub domain: String,
    pub os_version: String,
    pub install_date: Option<u64>,
    pub system_root: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn extracts_computer_identity_and_os_details_from_registry_exports() {
        let dir = tempfile::tempdir().expect("temp dir");
        let system_file = dir.path().join("system.reg");
        let winver_file = dir.path().join("winver.reg");

        strata_fs::write(
            &system_file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName]
"ComputerName"="WORKSTATION-01"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
"Domain"="corp.local"
"#,
        )
        .expect("write system reg");

        strata_fs::write(
            &winver_file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion]
"CurrentMajorVersionNumber"=dword:0000000a
"CurrentMinorVersionNumber"=dword:00000000
"CurrentBuildNumber"="22631"
"InstallDate"=dword:65f9f000
"SystemRoot"="C:\\Windows"
"#,
        )
        .expect("write winver reg");

        let info = get_computer_info_from_sources(&[system_file, winver_file]);
        assert_eq!(info.name, "WORKSTATION-01");
        assert_eq!(info.domain, "corp.local");
        assert_eq!(info.os_version, "10.0.22631");
        assert_eq!(info.system_root, "C:\\Windows");
        assert!(info.install_date.is_some());
    }
}

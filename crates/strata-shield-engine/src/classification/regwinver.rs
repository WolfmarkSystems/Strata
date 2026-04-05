use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, find_first_string_value, load_reg_records, parse_reg_u32,
    parse_reg_u64,
};

pub fn get_windows_version() -> WindowsVersion {
    get_windows_version_from_reg(&default_reg_path("winver.reg"))
}

pub fn get_windows_version_from_reg(path: &Path) -> WindowsVersion {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("microsoft\\windows nt\\currentversion")
    }) {
        let build = record
            .values
            .get("CurrentBuildNumber")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| {
                record
                    .values
                    .get("CurrentBuild")
                    .and_then(|v| decode_reg_string(v))
            })
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        WindowsVersion {
            major: record
                .values
                .get("CurrentMajorVersionNumber")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0),
            minor: record
                .values
                .get("CurrentMinorVersionNumber")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0),
            build,
            platform_id: record
                .values
                .get("PlatformId")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(2),
        }
    } else {
        WindowsVersion::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct WindowsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub platform_id: u32,
}

pub fn get_install_date() -> Option<u64> {
    get_install_date_from_reg(&default_reg_path("winver.reg"))
}

pub fn get_install_date_from_reg(path: &Path) -> Option<u64> {
    let records = load_reg_records(path);
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("microsoft\\windows nt\\currentversion")
    }) {
        if let Some(raw) = record.values.get("InstallDate") {
            return parse_reg_u64(raw);
        }
    }
    None
}

pub fn get_owner_info() -> OwnerInfo {
    get_owner_info_from_reg(&default_reg_path("winver.reg"))
}

pub fn get_owner_info_from_reg(path: &Path) -> OwnerInfo {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("microsoft\\windows nt\\currentversion")
    }) {
        OwnerInfo {
            registered_owner: find_first_string_value(record, &["RegisteredOwner"])
                .unwrap_or_default(),
            registered_org: find_first_string_value(record, &["RegisteredOrganization"])
                .unwrap_or_default(),
            product_id: find_first_string_value(record, &["ProductId"]).unwrap_or_default(),
        }
    } else {
        OwnerInfo::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct OwnerInfo {
    pub registered_owner: String,
    pub registered_org: String,
    pub product_id: String,
}

pub fn get_system_root() -> String {
    get_system_root_from_reg(&default_reg_path("winver.reg"))
}

pub fn get_system_root_from_reg(path: &Path) -> String {
    let records = load_reg_records(path);
    for record in &records {
        if let Some(root) = record
            .values
            .get("SystemRoot")
            .and_then(|raw| decode_reg_string(raw))
        {
            if !root.is_empty() {
                return root;
            }
        }
    }
    "C:\\Windows".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_windows_version_fields() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("winver.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion]
"CurrentMajorVersionNumber"=dword:0000000a
"CurrentMinorVersionNumber"=dword:00000000
"CurrentBuildNumber"="22631"
"InstallDate"=dword:65f9f000
"RegisteredOwner"="Examiner"
"#,
        )
        .unwrap();
        let v = get_windows_version_from_reg(&file);
        assert_eq!(v.major, 10);
        assert_eq!(v.build, 22631);
        assert!(get_install_date_from_reg(&file).is_some());
    }
}

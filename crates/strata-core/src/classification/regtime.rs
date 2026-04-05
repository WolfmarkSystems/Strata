use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records, parse_reg_u32};

pub fn get_timezone_info() -> TimezoneInfo {
    get_timezone_info_from_reg(&default_reg_path("time.reg"))
}

pub fn get_timezone_info_from_reg(path: &Path) -> TimezoneInfo {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\timezoneinformation")
    }) {
        TimezoneInfo {
            bias: record
                .values
                .get("Bias")
                .and_then(|v| parse_reg_u32(v))
                .map(|v| v as i32)
                .unwrap_or(0),
            standard_name: record
                .values
                .get("StandardName")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            daylight_name: record
                .values
                .get("DaylightName")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
        }
    } else {
        TimezoneInfo::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct TimezoneInfo {
    pub bias: i32,
    pub standard_name: String,
    pub daylight_name: String,
}

pub fn get_time_settings() -> TimeSettings {
    get_time_settings_from_reg(&default_reg_path("time.reg"))
}

pub fn get_time_settings_from_reg(path: &Path) -> TimeSettings {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\services\\w32time\\parameters")
    }) {
        TimeSettings {
            ntp_server: record
                .values
                .get("NtpServer")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            ntp_enabled: record
                .values
                .get("Type")
                .and_then(|v| decode_reg_string(v))
                .map(|v| !v.eq_ignore_ascii_case("NoSync"))
                .unwrap_or(false),
        }
    } else {
        TimeSettings::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct TimeSettings {
    pub ntp_server: String,
    pub ntp_enabled: bool,
}

pub fn get_auto_update() -> AutoUpdateSettings {
    get_auto_update_from_reg(&default_reg_path("time.reg"))
}

pub fn get_auto_update_from_reg(path: &Path) -> AutoUpdateSettings {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\services\\w32time\\timeproviders\\ntpclient")
    }) {
        AutoUpdateSettings {
            enabled: record
                .values
                .get("Enabled")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            update_server: record
                .values
                .get("NtpServer")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
        }
    } else {
        AutoUpdateSettings::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct AutoUpdateSettings {
    pub enabled: bool,
    pub update_server: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_time_registry_config() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("time.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation]
"Bias"=dword:0000012c
"StandardName"="Eastern Standard Time"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters]
"Type"="NTP"
"NtpServer"="time.windows.com,0x9"
"#,
        )
        .unwrap();
        let info = get_timezone_info_from_reg(&file);
        assert_eq!(info.bias, 300);
        let settings = get_time_settings_from_reg(&file);
        assert!(settings.ntp_enabled);
    }
}

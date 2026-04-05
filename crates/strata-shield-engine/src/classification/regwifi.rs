use std::collections::BTreeSet;
use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32,
};

pub fn get_wifi_autoconnect() -> Vec<WifiAutoConnect> {
    get_wifi_autoconnect_from_reg(&default_reg_path("wifi.reg"))
}

pub fn get_wifi_autoconnect_from_reg(path: &Path) -> Vec<WifiAutoConnect> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\microsoft\\wlan\\"))
    {
        let profile_name = record
            .values
            .get("ProfileName")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| key_leaf(&record.path));
        let ssid = record
            .values
            .get("SSID")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| profile_name.clone());
        let connect_mode = record
            .values
            .get("ConnectionMode")
            .and_then(|v| parse_reg_u32(v))
            .unwrap_or(0);

        if connect_mode != 0 || record.values.contains_key("AutoConnect") {
            out.push(WifiAutoConnect { ssid, profile_name });
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct WifiAutoConnect {
    pub ssid: String,
    pub profile_name: String,
}

pub fn get_wifi_order() -> Vec<String> {
    get_wifi_order_from_reg(&default_reg_path("wifi.reg"))
}

pub fn get_wifi_order_from_reg(path: &Path) -> Vec<String> {
    let mut order = BTreeSet::new();
    for profile in get_wireless_profiles_from_reg(path) {
        order.insert(profile.ssid);
    }
    order.into_iter().collect()
}

pub fn get_wireless_profiles() -> Vec<WifiProfileReg> {
    get_wireless_profiles_from_reg(&default_reg_path("wifi.reg"))
}

pub fn get_wireless_profiles_from_reg(path: &Path) -> Vec<WifiProfileReg> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\microsoft\\wlan\\"))
    {
        let ssid = record
            .values
            .get("SSID")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| {
                record
                    .values
                    .get("ProfileName")
                    .and_then(|v| decode_reg_string(v))
                    .unwrap_or_else(|| key_leaf(&record.path))
            });
        let authentication = record
            .values
            .get("Authentication")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| "Unknown".to_string());
        let encryption = record
            .values
            .get("Encryption")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| "Unknown".to_string());

        out.push(WifiProfileReg {
            ssid,
            authentication,
            encryption,
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct WifiProfileReg {
    pub ssid: String,
    pub authentication: String,
    pub encryption: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_wifi_profile_export() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("wifi.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wlan\Profiles\{GUID}]
"ProfileName"="CorpWifi"
"SSID"="CorpWifi"
"Authentication"="WPA2PSK"
"Encryption"="AES"
"ConnectionMode"=dword:00000001
"#,
        )
        .unwrap();
        let profiles = get_wireless_profiles_from_reg(&file);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].ssid, "CorpWifi");
        assert_eq!(get_wifi_autoconnect_from_reg(&file).len(), 1);
    }
}

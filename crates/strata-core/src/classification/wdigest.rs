use std::path::Path;

use super::reg_export::{default_reg_path, load_reg_records, parse_reg_u32};

pub fn get_wdigest_config() -> WdigestConfig {
    get_wdigest_config_from_reg(&default_reg_path("security.reg"))
}

pub fn get_wdigest_config_from_reg(path: &Path) -> WdigestConfig {
    let records = load_reg_records(path);

    if let Some(record) = records.iter().find(|record| {
        record
            .path
            .to_ascii_lowercase()
            .contains("\\control\\securityproviders\\wdigest")
    }) {
        let use_logon_credential = record
            .values
            .get("UseLogonCredential")
            .and_then(|value| parse_reg_u32(value));

        let negotiate = record
            .values
            .get("Negotiate")
            .and_then(|value| parse_reg_u32(value));

        return WdigestConfig {
            enabled: use_logon_credential.unwrap_or(0) != 0,
            use_logon_credential,
            negotiate,
            source_key: record.path.clone(),
        };
    }

    WdigestConfig::default()
}

#[derive(Debug, Clone, Default)]
pub struct WdigestConfig {
    pub enabled: bool,
    pub use_logon_credential: Option<u32>,
    pub negotiate: Option<u32>,
    pub source_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_wdigest_use_logon_credential() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("security.reg");

        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest]
"UseLogonCredential"=dword:00000001
"Negotiate"=dword:00000001
"#,
        )
        .expect("write reg");

        let cfg = get_wdigest_config_from_reg(&file);
        assert!(cfg.enabled);
        assert_eq!(cfg.use_logon_credential, Some(1));
        assert_eq!(cfg.negotiate, Some(1));
        assert!(cfg.source_key.to_ascii_lowercase().contains("wdigest"));
    }

    #[test]
    fn defaults_when_wdigest_key_is_missing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("security.reg");
        strata_fs::write(&file, "Windows Registry Editor Version 5.00\n").expect("write reg");

        let cfg = get_wdigest_config_from_reg(&file);
        assert!(!cfg.enabled);
        assert_eq!(cfg.use_logon_credential, None);
    }
}

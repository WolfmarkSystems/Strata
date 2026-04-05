use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records, parse_reg_u32};

pub fn get_typed_urls_history() -> Vec<TypedUrl> {
    get_typed_urls_history_from_reg(&default_reg_path("proxy.reg"))
}

pub fn get_typed_urls_history_from_reg(path: &Path) -> Vec<TypedUrl> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\internet explorer\\typedurls")
    }) {
        for (name, raw) in &record.values {
            if name.to_ascii_lowercase().starts_with("url") {
                if let Some(url) = decode_reg_string(raw) {
                    out.push(TypedUrl {
                        url,
                        visit_time: None,
                    });
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct TypedUrl {
    pub url: String,
    pub visit_time: Option<u64>,
}

pub fn get_bfcache() -> Vec<BfcacheEntry> {
    get_bfcache_from_reg(&default_reg_path("proxy.reg"))
}

pub fn get_bfcache_from_reg(path: &Path) -> Vec<BfcacheEntry> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("bfcache"))
    {
        for raw in record.values.values() {
            if let Some(url) = decode_reg_string(raw) {
                out.push(BfcacheEntry {
                    url,
                    timestamp: None,
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct BfcacheEntry {
    pub url: String,
    pub timestamp: Option<u64>,
}

pub fn get_proxy_settings() -> ProxySettings {
    get_proxy_settings_from_reg(&default_reg_path("proxy.reg"))
}

pub fn get_proxy_settings_from_reg(path: &Path) -> ProxySettings {
    let records = load_reg_records(path);
    if let Some(record) = records
        .iter()
        .find(|r| r.path.to_ascii_lowercase().contains("\\internet settings"))
    {
        ProxySettings {
            proxy_enable: record
                .values
                .get("ProxyEnable")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            proxy_server: record
                .values
                .get("ProxyServer")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            proxy_override: record
                .values
                .get("ProxyOverride")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
        }
    } else {
        ProxySettings::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProxySettings {
    pub proxy_enable: bool,
    pub proxy_server: String,
    pub proxy_override: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_proxy_settings() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("proxy.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings]
"ProxyEnable"=dword:00000001
"ProxyServer"="127.0.0.1:8080"
"ProxyOverride"="<local>"
"#,
        )
        .unwrap();
        let p = get_proxy_settings_from_reg(&file);
        assert!(p.proxy_enable);
        assert_eq!(p.proxy_server, "127.0.0.1:8080");
    }
}

use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records};

pub fn get_typed_urls() -> Vec<UrlEntry> {
    get_typed_urls_from_reg(&default_reg_path("url.reg"))
}

pub fn get_typed_urls_from_reg(path: &Path) -> Vec<UrlEntry> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\microsoft\\internet explorer\\typedurls")
    }) {
        for (name, raw) in &record.values {
            if name.to_ascii_lowercase().starts_with("url") {
                if let Some(url) = decode_reg_string(raw) {
                    out.push(UrlEntry {
                        url,
                        timestamp: None,
                    });
                }
            }
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct UrlEntry {
    pub url: String,
    pub timestamp: Option<u64>,
}

pub fn get_iexplore_urls() -> Vec<UrlEntry> {
    get_typed_urls()
}

pub fn get_firefox_urls() -> Vec<UrlEntry> {
    get_browser_urls_from_reg(&default_reg_path("url.reg"), "firefox")
}

pub fn get_chrome_urls() -> Vec<UrlEntry> {
    get_browser_urls_from_reg(&default_reg_path("url.reg"), "chrome")
}

pub fn get_edge_urls() -> Vec<UrlEntry> {
    get_browser_urls_from_reg(&default_reg_path("url.reg"), "edge")
}

fn get_browser_urls_from_reg(path: &Path, browser: &str) -> Vec<UrlEntry> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    let marker = format!("\\{browser}\\");

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains(&marker))
    {
        for raw in record.values.values() {
            if let Some(value) = decode_reg_string(raw) {
                if value.starts_with("http://") || value.starts_with("https://") {
                    out.push(UrlEntry {
                        url: value,
                        timestamp: None,
                    });
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_ie_typed_urls() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("url.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLs]
"url1"="https://example.org"
"url2"="http://test.local"
"#,
        )
        .unwrap();
        let urls = get_typed_urls_from_reg(&file);
        assert_eq!(urls.len(), 2);
    }
}

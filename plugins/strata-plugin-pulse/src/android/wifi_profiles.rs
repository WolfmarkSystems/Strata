//! Wi-Fi profiles — saved networks from `WifiConfigStore.xml`.
//!
//! ALEAPP reference: `scripts/artifacts/wifiProfiles.py`. Source path:
//! `/data/misc/wifi/WifiConfigStore.xml` (Android 8+) or
//! `/data/misc/wifi/wpa_supplicant.conf` on older devices.
//!
//! Pulse parses the XML form by string-extraction — full XML parsing
//! pulls in another dependency we do not need here. Each `<string
//! name="SSID">"FooBar"</string>` block becomes one record.

use crate::android::helpers::build_record;
use std::fs;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "wificonfigstore.xml",
    "wpa_supplicant.conf",
    "/wifi/networkrequeststore.xml",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ssid in extract_ssids(&text) {
        out.push(build_record(
            ArtifactCategory::NetworkArtifacts,
            "Android Wi-Fi Profile",
            format!("Wi-Fi: {}", ssid),
            format!("Saved Wi-Fi network SSID='{}'", ssid),
            path,
            None,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

/// Pull SSIDs out of `WifiConfigStore.xml` style content. Looks for
/// either `<string name="SSID">"foo"</string>` (Android 8+ XML) or
/// `ssid="foo"` (older `wpa_supplicant.conf`).
fn extract_ssids(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    // XML form
    let needle = "<string name=\"SSID\">";
    let mut cursor = 0;
    while let Some(start) = text[cursor..].find(needle) {
        let abs = cursor + start + needle.len();
        if let Some(end) = text[abs..].find("</string>") {
            let raw = text[abs..abs + end].trim();
            let cleaned = raw.trim_matches('"').to_string();
            if !cleaned.is_empty() {
                out.push(cleaned);
            }
            cursor = abs + end;
        } else {
            break;
        }
    }
    // wpa_supplicant form
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("ssid=") {
            let cleaned = rest.trim_matches('"').to_string();
            if !cleaned.is_empty() {
                out.push(cleaned);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(content: &str) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(content.as_bytes()).unwrap();
        tmp
    }

    #[test]
    fn parses_xml_form() {
        let xml = r#"
        <NetworkList>
          <Network>
            <string name="SSID">"HomeNetwork"</string>
          </Network>
          <Network>
            <string name="SSID">"CoffeeShop"</string>
          </Network>
        </NetworkList>
        "#;
        let f = write_tmp(xml);
        let r = parse(f.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().any(|x| x.title == "Wi-Fi: HomeNetwork"));
        assert!(r.iter().any(|x| x.title == "Wi-Fi: CoffeeShop"));
    }

    #[test]
    fn parses_wpa_supplicant_form() {
        let conf = r#"
        network={
            ssid="LegacyNet"
            psk="hunter2"
        }
        network={
            ssid="OtherNet"
        }
        "#;
        let f = write_tmp(conf);
        let r = parse(f.path());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn missing_file_yields_empty() {
        let r = parse(Path::new("/definitely/not/here/wifi.xml"));
        assert!(r.is_empty());
    }

    #[test]
    fn empty_file_yields_empty() {
        let f = write_tmp("");
        assert!(parse(f.path()).is_empty());
    }
}

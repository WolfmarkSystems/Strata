//! Bluetooth — paired devices and Bluetooth-related artifacts.
//!
//! ALEAPP reference: `scripts/artifacts/bluetoothPaired.py`,
//! `scripts/artifacts/bluetoothOther.py`. Source paths:
//!
//! - `/data/misc/bluedroid/bt_config.conf` — INI-style file containing
//!   `[XX:XX:XX:XX:XX:XX]` sections per paired device with `Name`,
//!   `LinkKey`, `Timestamp`, etc.
//! - Alternatively, the `btopp.db` SQLite database with the
//!   `btopp` (object push) transfer table.
//!
//! Pulse parses the INI form because that is the canonical paired
//! device list. Each MAC-section becomes one record.

use crate::android::helpers::build_record;
use std::fs;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["bt_config.conf", "btopp.db", "bt_config.bak"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_bt_config(&text, path)
}

/// Parse `bt_config.conf` INI sections. Each `[MAC]` section becomes
/// one paired-device record. Section bodies expose `Name = ...`.
fn parse_bt_config(text: &str, path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let mut current_mac: Option<String> = None;
    let mut current_name: Option<String> = None;

    let flush =
        |mac: &mut Option<String>, name: &mut Option<String>, out: &mut Vec<ArtifactRecord>| {
            if let Some(m) = mac.take() {
                let n = name.take().unwrap_or_else(|| "(unknown)".to_string());
                out.push(build_record(
                    ArtifactCategory::NetworkArtifacts,
                    "Android Bluetooth Paired",
                    format!("BT: {} ({})", n, m),
                    format!("Bluetooth paired device name='{}' mac='{}'", n, m),
                    path,
                    None,
                    ForensicValue::Medium,
                    false,
                ));
            }
        };

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // New section — flush prior, start new.
            flush(&mut current_mac, &mut current_name, &mut out);
            let inner = &trimmed[1..trimmed.len() - 1];
            if is_mac_address(inner) {
                current_mac = Some(inner.to_string());
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Name = ") {
            current_name = Some(rest.to_string());
        } else if let Some(rest) = trimmed.strip_prefix("Name=") {
            current_name = Some(rest.to_string());
        }
    }
    flush(&mut current_mac, &mut current_name, &mut out);
    out
}

/// Loose MAC-address check — six pairs of hex separated by colons.
fn is_mac_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
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
    fn parses_two_paired_devices() {
        let conf = r#"
        [Adapter]
        Address = AA:BB:CC:DD:EE:FF

        [11:22:33:44:55:66]
        Name = Sony WH-1000XM4
        LinkKey = abcd

        [77:88:99:AA:BB:CC]
        Name = Tesla Model 3
        LinkKey = efgh
        "#;
        let f = write_tmp(conf);
        let r = parse(f.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().any(|x| x.title.contains("Sony WH-1000XM4")));
        assert!(r.iter().any(|x| x.title.contains("Tesla Model 3")));
    }

    #[test]
    fn detail_includes_mac_address() {
        let conf = "[11:22:33:44:55:66]\nName = MyHeadset\n";
        let f = write_tmp(conf);
        let r = parse(f.path());
        assert!(r[0].detail.contains("11:22:33:44:55:66"));
        assert!(r[0].detail.contains("MyHeadset"));
    }

    #[test]
    fn missing_file_yields_empty() {
        assert!(parse(Path::new("/no/such/bt_config.conf")).is_empty());
    }

    #[test]
    fn empty_file_yields_empty() {
        let f = write_tmp("");
        assert!(parse(f.path()).is_empty());
    }

    #[test]
    fn mac_validator_rejects_garbage() {
        assert!(is_mac_address("AA:BB:CC:DD:EE:FF"));
        assert!(!is_mac_address("Adapter"));
        assert!(!is_mac_address("11:22:33:44:55"));
    }
}

//! Installed apps — package list from `packages.xml` / `packages.list`.
//!
//! ALEAPP reference: `scripts/artifacts/installedAppsLibrary.py`,
//! `scripts/artifacts/packageManagerInstalledApps.py`. Source paths:
//!
//! - `/data/system/packages.list` — line per package, fields delimited
//!   by whitespace: `<package> <uid> <debug_flag> <data_dir> <seinfo>
//!   <gids> <profileable> <apk_path>`.
//! - `/data/system/packages.xml` — fully detailed XML form, but the
//!   `.list` form is enough for forensic enumeration.
//!
//! Pulse parses the `.list` form because it is text-based, never
//! corrupted, and present on every Android version.

use crate::android::helpers::build_record;
use std::fs;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["packages.list", "packages.xml"];

/// Some package names that — while real — frequently appear on jailbroken
/// or "modded" devices and warrant a closer look.
const SUSPICIOUS_PACKAGES: &[&str] = &[
    "com.topjohnwu.magisk", // Magisk root manager
    "eu.chainfire.supersu", // SuperSU
    "com.koushikdutta.superuser",
    "stericson.busybox",      // BusyBox installer
    "de.robv.android.xposed", // Xposed
    "io.va.exposed",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('<') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let package = match parts.next() {
            Some(p) => p,
            None => continue,
        };
        let uid = parts.next().unwrap_or("");
        let data_dir = parts.nth(1).unwrap_or("");
        let suspicious = SUSPICIOUS_PACKAGES
            .iter()
            .any(|s| package.eq_ignore_ascii_case(s));
        let value = if suspicious {
            ForensicValue::High
        } else {
            ForensicValue::Low
        };
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Android Installed App",
            format!("App: {}", package),
            format!(
                "Installed package='{}' uid='{}' data_dir='{}'",
                package, uid, data_dir
            ),
            path,
            None,
            value,
            suspicious,
        ));
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
    fn parses_two_packages() {
        let txt = "com.android.chrome 10042 0 /data/user/0/com.android.chrome default 1023,1024,1077 0 /system/app/Chrome.apk\n\
                   com.example.app 10100 0 /data/user/0/com.example.app default 1023 0 /data/app/example.apk\n";
        let f = write_tmp(txt);
        let r = parse(f.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().any(|x| x.title == "App: com.android.chrome"));
        assert!(r.iter().any(|x| x.title == "App: com.example.app"));
    }

    #[test]
    fn flags_root_managers() {
        let txt = "com.topjohnwu.magisk 10080 0 /data/user/0/com.topjohnwu.magisk default 1023 0 /data/app/magisk.apk\n";
        let f = write_tmp(txt);
        let r = parse(f.path());
        assert_eq!(r.len(), 1);
        assert!(r[0].is_suspicious);
        assert_eq!(r[0].forensic_value, ForensicValue::High);
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        let txt =
            "\n# header comment\ncom.app1 10001 0 /data/user/0/com.app1 default 1023 0 /a.apk\n\n";
        let f = write_tmp(txt);
        let r = parse(f.path());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn missing_file_yields_empty() {
        assert!(parse(Path::new("/no/such/packages.list")).is_empty());
    }
}

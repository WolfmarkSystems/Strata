//! Device info — `build.prop` style key/value extraction.
//!
//! ALEAPP reference: `scripts/artifacts/buildProp.py`. Source paths:
//!
//! - `/system/build.prop`
//! - `/vendor/build.prop`
//! - `/system/etc/build.prop`
//!
//! Each `key=value` line becomes one record. Forensically interesting
//! keys (model, manufacturer, serial, fingerprint, security patch
//! level) are tagged Medium; the rest stay Informational.

use crate::android::helpers::build_record;
use std::fs;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["build.prop", "default.prop"];

const HIGH_VALUE_KEYS: &[&str] = &[
    "ro.product.model",
    "ro.product.manufacturer",
    "ro.serialno",
    "ro.build.fingerprint",
    "ro.build.version.security_patch",
    "ro.build.version.release",
    "ro.build.id",
    "ro.boot.serialno",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            continue;
        }
        let high = HIGH_VALUE_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key));
        let fv = if high {
            ForensicValue::Medium
        } else {
            ForensicValue::Informational
        };
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Android Device Property",
            format!("{} = {}", key, value),
            format!("build.prop key='{}' value='{}'", key, value),
            path,
            None,
            fv,
            false,
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
    fn parses_keys_skips_comments() {
        let txt = "# This is a comment\nro.product.model=Pixel 7\nro.product.manufacturer=Google\nro.build.id=TQ3A.230805.001\n\n";
        let f = write_tmp(txt);
        let r = parse(f.path());
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn high_value_keys_tagged_medium() {
        let txt = "ro.product.model=Pixel 7\nro.foo.bar=baz\n";
        let f = write_tmp(txt);
        let r = parse(f.path());
        let model = r.iter().find(|x| x.title.starts_with("ro.product.model")).unwrap();
        assert_eq!(model.forensic_value, ForensicValue::Medium);
        let foo = r.iter().find(|x| x.title.starts_with("ro.foo.bar")).unwrap();
        assert_eq!(foo.forensic_value, ForensicValue::Informational);
    }

    #[test]
    fn detail_includes_value() {
        let txt = "ro.serialno=ABCD1234\n";
        let f = write_tmp(txt);
        let r = parse(f.path());
        assert!(r[0].detail.contains("ABCD1234"));
    }

    #[test]
    fn missing_file_yields_empty() {
        assert!(parse(Path::new("/no/such/build.prop")).is_empty());
    }
}

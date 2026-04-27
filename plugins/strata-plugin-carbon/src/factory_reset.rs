//! Android factory-reset detection (AND-1).
//!
//! Most reliable indicator is the empty `/data/misc/bootstat/
//! factory_reset` file — its mtime marks the wipe. Other sources
//! (device_policies.xml last_wipe_time, Samsung resetinfo dir,
//! bootstat persistent_boot_stat) are corroborating.
//!
//! MITRE: T1485 (data destruction), T1070 (indicator removal).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::fs;
use std::path::Path;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidFactoryReset {
    pub reset_time: Option<DateTime<Utc>>,
    pub source_artifact: String,
    pub device_oem: String,
    pub confidence: String,
    pub corroborating_artifacts: Vec<String>,
    pub caveats: Vec<String>,
}

pub fn is_factory_reset_path(path: &Path) -> bool {
    let lower = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    if name == "factory_reset" && lower.contains("/bootstat/") {
        return true;
    }
    if name == "persistent_boot_stat" && lower.contains("/bootstat/") {
        return true;
    }
    if name == "device_policies.xml" && lower.contains("/data/system/") {
        return true;
    }
    false
}

fn oem_hint(path: &Path) -> &'static str {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if lower.contains("samsung") || lower.contains("knox") {
        "Samsung"
    } else if lower.contains("pixel") || lower.contains("google") {
        "Pixel"
    } else {
        "Unknown"
    }
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    if !is_factory_reset_path(path) {
        return Vec::new();
    }
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let reset_time = meta.modified().ok().map(DateTime::<Utc>::from);
    let (source_artifact, confidence) = match name.as_str() {
        "factory_reset" => (
            "bootstat/factory_reset (empty file mtime)".to_string(),
            "High".to_string(),
        ),
        "persistent_boot_stat" => (
            "bootstat/persistent_boot_stat".to_string(),
            "Medium".to_string(),
        ),
        "device_policies.xml" => (
            "device_policies.xml last_wipe_time".to_string(),
            "Medium".to_string(),
        ),
        _ => ("unknown".to_string(), "Low".to_string()),
    };
    let mut caveats = vec![
        "Artifact availability depends on OEM and Android version".to_string(),
        "Physical / FFS extraction required for most reset indicators; logical may miss them"
            .to_string(),
        "Some OEMs clear bootstat on reset — absence is inconclusive".to_string(),
    ];
    if name == "device_policies.xml" {
        if let Ok(body) = fs::read_to_string(path) {
            if let Some(value) = extract_xml_attr(&body, "last_wipe_time") {
                if let Ok(secs) = value.parse::<i64>() {
                    if let Some(dt) = DateTime::<Utc>::from_timestamp(secs / 1000, 0) {
                        caveats.push(format!(
                            "device_policies.xml last_wipe_time = {}",
                            dt.format("%Y-%m-%d %H:%M:%S UTC")
                        ));
                    }
                }
            }
        }
    }
    let record = AndroidFactoryReset {
        reset_time,
        source_artifact: source_artifact.clone(),
        device_oem: oem_hint(path).to_string(),
        confidence: confidence.clone(),
        corroborating_artifacts: Vec::new(),
        caveats: caveats.clone(),
    };
    let path_str = path.to_string_lossy().to_string();
    let mut a = Artifact::new("Android Factory Reset", &path_str);
    a.timestamp = record.reset_time.map(|d| d.timestamp() as u64);
    a.add_field(
        "title",
        &format!(
            "Android factory reset indicator: {}",
            record.source_artifact
        ),
    );
    a.add_field(
        "detail",
        &format!(
            "Source: {} | OEM: {} | Confidence: {} | Reset time: {}",
            record.source_artifact,
            record.device_oem,
            record.confidence,
            record
                .reset_time
                .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        ),
    );
    a.add_field("file_type", "Android Factory Reset");
    a.add_field("device_oem", &record.device_oem);
    a.add_field("confidence", &record.confidence);
    a.add_field("source_artifact", &record.source_artifact);
    for (i, caveat) in record.caveats.iter().enumerate() {
        a.add_field(if i == 0 { "caveat" } else { "caveat_extra" }, caveat);
    }
    a.add_field("mitre", "T1485");
    a.add_field("mitre_secondary", "T1070");
    a.add_field("forensic_value", "High");
    a.add_field("suspicious", "true");
    vec![a]
}

fn extract_xml_attr(body: &str, attr: &str) -> Option<String> {
    let needle = format!("{}=\"", attr);
    let pos = body.find(&needle)? + needle.len();
    let end = body[pos..].find('"')?;
    Some(body[pos..pos + end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_factory_reset_path_matches_bootstat_file() {
        assert!(is_factory_reset_path(Path::new(
            "/data/misc/bootstat/factory_reset"
        )));
        assert!(is_factory_reset_path(Path::new(
            "/data/misc/bootstat/persistent_boot_stat"
        )));
        assert!(is_factory_reset_path(Path::new(
            "/data/system/device_policies.xml"
        )));
        assert!(!is_factory_reset_path(Path::new(
            "/data/misc/other/factory_reset"
        )));
        assert!(!is_factory_reset_path(Path::new("/tmp/random")));
    }

    #[test]
    fn scan_reads_mtime_from_empty_factory_reset_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bootstat = dir.path().join("data").join("misc").join("bootstat");
        std::fs::create_dir_all(&bootstat).expect("mkdirs");
        let path = bootstat.join("factory_reset");
        std::fs::write(&path, b"").expect("w");
        let out = scan(&path);
        assert_eq!(out.len(), 1);
        let art = &out[0];
        assert_eq!(art.data.get("confidence").map(|s| s.as_str()), Some("High"));
        assert_eq!(
            art.data.get("file_type").map(|s| s.as_str()),
            Some("Android Factory Reset")
        );
    }

    #[test]
    fn scan_extracts_last_wipe_time_attribute() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sys = dir.path().join("data").join("system");
        std::fs::create_dir_all(&sys).expect("mkdirs");
        let path = sys.join("device_policies.xml");
        std::fs::write(
            &path,
            b"<policies><admin last_wipe_time=\"1717243200000\"/></policies>",
        )
        .expect("w");
        let out = scan(&path);
        assert!(out.iter().any(|a| a
            .data
            .get("caveat_extra")
            .map(|s| s.contains("last_wipe_time"))
            .unwrap_or(false)));
    }

    #[test]
    fn oem_hint_recognises_samsung_and_pixel_path_fragments() {
        assert_eq!(
            oem_hint(Path::new("/data/samsung/bootstat/factory_reset")),
            "Samsung"
        );
        assert_eq!(
            oem_hint(Path::new("/data/google/pixel/bootstat/factory_reset")),
            "Pixel"
        );
        assert_eq!(
            oem_hint(Path::new("/data/misc/bootstat/factory_reset")),
            "Unknown"
        );
    }

    #[test]
    fn scan_noop_on_unrelated_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("random.txt");
        std::fs::write(&path, b"hi").expect("w");
        assert!(scan(&path).is_empty());
    }
}

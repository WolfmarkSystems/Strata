use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::DateTime;

use super::reg_export::default_reg_path;
use super::regdefendercfg;
use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use crate::errors::ForensicError;

pub fn check_windows_defender_status() -> Result<DefenderStatus, ForensicError> {
    check_windows_defender_status_from_sources(
        &default_reg_path("defender.reg"),
        &default_mplog_paths(),
    )
}

pub fn check_windows_defender_status_from_sources(
    reg_path: &Path,
    log_paths: &[PathBuf],
) -> Result<DefenderStatus, ForensicError> {
    let cfg = regdefendercfg::get_windows_defender_config_from_reg(reg_path);
    let exclusions = regdefendercfg::get_defender_exclusions_from_reg(reg_path);
    let detections = parse_defender_detections_from_logs(log_paths);

    Ok(DefenderStatus {
        enabled: cfg.realtime_protection || cfg.behavior_monitoring || cfg.script_scanning,
        real_time_protection: cfg.realtime_protection,
        exclusions_count: exclusions.len(),
        detections_count: detections.len(),
        tamper_protection_suspected: cfg.realtime_protection && cfg.behavior_monitoring,
    })
}

#[derive(Debug, Clone, Default)]
pub struct DefenderStatus {
    pub enabled: bool,
    pub real_time_protection: bool,
    pub exclusions_count: usize,
    pub detections_count: usize,
    pub tamper_protection_suspected: bool,
}

pub fn get_defender_settings() -> Result<DefenderSettings, ForensicError> {
    get_defender_settings_from_sources(&default_reg_path("defender.reg"), &default_mplog_paths())
}

pub fn get_defender_settings_from_sources(
    reg_path: &Path,
    log_paths: &[PathBuf],
) -> Result<DefenderSettings, ForensicError> {
    let cfg = regdefendercfg::get_windows_defender_config_from_reg(reg_path);
    let exclusions = regdefendercfg::get_defender_exclusions_from_reg(reg_path);
    let detections = parse_defender_detections_from_logs(log_paths);

    let quarantined_items = detections
        .iter()
        .filter(|d| d.action.to_ascii_lowercase().contains("quarant"))
        .filter_map(|d| d.path.clone())
        .collect::<Vec<_>>();

    Ok(DefenderSettings {
        cloud_delivery: cfg.behavior_monitoring,
        sample_submission: cfg.script_scanning,
        excluded_paths: exclusions,
        quarantined_items,
        detections,
    })
}

#[derive(Debug, Clone, Default)]
pub struct DefenderSettings {
    pub cloud_delivery: bool,
    pub sample_submission: bool,
    pub excluded_paths: Vec<String>,
    pub quarantined_items: Vec<String>,
    pub detections: Vec<DefenderDetection>,
}

#[derive(Debug, Clone, Default)]
pub struct DefenderDetection {
    pub timestamp: Option<u64>,
    pub threat_name: String,
    pub action: String,
    pub path: Option<String>,
    pub raw_line: String,
}

fn default_mplog_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();

    if let Ok(dir) = std::env::var("FORENSIC_DEFENDER_LOG_DIR") {
        collect_mplog_paths(Path::new(&dir), &mut out);
    }

    let artifacts_defender = PathBuf::from("artifacts").join("defender");
    collect_mplog_paths(&artifacts_defender, &mut out);

    let artifacts_logs = PathBuf::from("artifacts").join("logs");
    collect_mplog_paths(&artifacts_logs, &mut out);

    dedupe_paths(out)
}

fn collect_mplog_paths(dir: &Path, out: &mut Vec<PathBuf>) {
    if !dir.exists() {
        return;
    }

    let direct = dir.join("MPLog.log");
    if direct.exists() {
        out.push(direct);
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = path
            .file_name()
            .map(|v| v.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if file_name.starts_with("mplog") && file_name.ends_with(".log") {
            out.push(path);
        }
    }
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for path in paths {
        if seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

fn parse_defender_detections_from_logs(paths: &[PathBuf]) -> Vec<DefenderDetection> {
    let mut out = Vec::new();

    for path in paths {
        let Ok(content) = read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 4) else {
            continue;
        };

        for line in content.lines() {
            if let Some(detection) = parse_mplog_detection_line(line) {
                out.push(detection);
            }
        }
    }

    out
}

fn parse_mplog_detection_line(line: &str) -> Option<DefenderDetection> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if !(lower.contains("threat") || lower.contains("malware") || lower.contains("detected")) {
        return None;
    }

    let threat_name = extract_field(
        trimmed,
        &[
            "Threat Name=",
            "Threat=",
            "Threat:",
            "Detected:",
            "Malware Name=",
        ],
    )
    .unwrap_or_else(|| "UnknownThreat".to_string());

    let action = extract_field(trimmed, &["Action=", "Result=", "Disposition=", "Status="])
        .unwrap_or_else(|| "Detected".to_string());

    let path = extract_field(
        trimmed,
        &["Path=", "File=", "Resource=", "Target=", "Object="],
    )
    .filter(|v| !v.is_empty());

    Some(DefenderDetection {
        timestamp: parse_detection_timestamp(trimmed),
        threat_name,
        action,
        path,
        raw_line: trimmed.to_string(),
    })
}

fn parse_detection_timestamp(line: &str) -> Option<u64> {
    let first_token = line.split_whitespace().next().unwrap_or_default();
    if let Ok(parsed) = DateTime::parse_from_rfc3339(first_token) {
        return Some(parsed.timestamp() as u64);
    }

    if let Some(value) = extract_field(line, &["Time=", "Timestamp="]) {
        if let Ok(parsed) = DateTime::parse_from_rfc3339(value.trim()) {
            return Some(parsed.timestamp() as u64);
        }
        if let Ok(unix) = value.trim().parse::<u64>() {
            return Some(unix);
        }
    }

    None
}

fn extract_field(line: &str, markers: &[&str]) -> Option<String> {
    let lower = line.to_ascii_lowercase();

    for marker in markers {
        let marker_lower = marker.to_ascii_lowercase();
        let Some(start_idx) = lower.find(&marker_lower) else {
            continue;
        };
        let start = start_idx + marker.len();
        let rest = line.get(start..)?.trim_start();

        let mut end = rest.find(['|', ',', ';']).unwrap_or(rest.len());
        for (idx, ch) in rest.char_indices() {
            if ch != ' ' {
                continue;
            }
            let next = rest.get(idx + 1..).unwrap_or_default();
            if looks_like_key_assignment(next) {
                end = end.min(idx);
                break;
            }
        }
        let value = rest[..end].trim().trim_matches('"').to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }

    None
}

fn looks_like_key_assignment(candidate: &str) -> bool {
    let mut key_len = 0usize;
    for ch in candidate.chars() {
        if ch == '=' {
            return key_len > 0;
        }
        if !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '.')) {
            return false;
        }
        key_len += 1;
        if key_len > 48 {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_mplog_detection_line_extracts_fields() {
        let line = "2026-02-01T10:11:12Z Threat Name=Trojan:Win32/Test Action=Quarantine Path=C:\\Users\\Public\\bad.exe";
        let parsed = parse_mplog_detection_line(line).expect("parsed detection");
        assert_eq!(parsed.threat_name, "Trojan:Win32/Test");
        assert_eq!(parsed.action, "Quarantine");
        assert_eq!(parsed.path.as_deref(), Some("C:\\Users\\Public\\bad.exe"));
        assert!(parsed.timestamp.is_some());
    }

    #[test]
    fn check_windows_defender_status_from_sources_reads_reg_and_logs() {
        let dir = tempfile::tempdir().expect("temp dir");
        let reg = dir.path().join("defender.reg");
        let log = dir.path().join("MPLog-2026.log");

        strata_fs::write(
            &reg,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender]
"DisableRealtimeMonitoring"=dword:00000000
"DisableBehaviorMonitoring"=dword:00000000
"DisableScriptScanning"=dword:00000001
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths]
"C:\\Tools\\Allowed"=""
"#,
        )
        .expect("write reg");

        strata_fs::write(
            &log,
            "2026-02-01T10:11:12Z Threat Name=Trojan:Win32/Test Action=Quarantine Path=C:\\Users\\Public\\bad.exe\n",
        )
        .expect("write log");

        let status = check_windows_defender_status_from_sources(&reg, &[log]).expect("status");
        assert!(status.enabled);
        assert!(status.real_time_protection);
        assert_eq!(status.exclusions_count, 1);
        assert_eq!(status.detections_count, 1);
    }

    #[test]
    fn get_defender_settings_from_sources_includes_exclusions_and_quarantine() {
        let dir = tempfile::tempdir().expect("temp dir");
        let reg = dir.path().join("defender.reg");
        let log = dir.path().join("MPLog.log");

        strata_fs::write(
            &reg,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender]
"DisableRealtimeMonitoring"=dword:00000000
"DisableBehaviorMonitoring"=dword:00000000
"DisableScriptScanning"=dword:00000000
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths]
"C:\\Forensics\\Ignore"=""
"#,
        )
        .expect("write reg");

        strata_fs::write(
            &log,
            "2026-02-01T10:11:12Z Threat Name=Worm:Win32/Sample Action=Quarantine Path=C:\\Temp\\sample.exe\n",
        )
        .expect("write log");

        let settings = get_defender_settings_from_sources(&reg, &[log]).expect("settings");
        assert!(settings.cloud_delivery);
        assert!(settings.sample_submission);
        assert_eq!(settings.excluded_paths, vec!["C:\\Forensics\\Ignore"]);
        assert_eq!(settings.detections.len(), 1);
        assert_eq!(settings.quarantined_items, vec!["C:\\Temp\\sample.exe"]);
    }
}

use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use crate::errors::ForensicError;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ErrorReport {
    pub report_id: String,
    pub app_name: Option<String>,
    pub app_version: Option<String>,
    pub description: Option<String>,
    pub event_type: Option<String>,
    pub date: Option<i64>,
    pub status: Option<String>,
    pub bucket: Option<String>,
    pub files: Vec<String>,
}

pub fn parse_error_reports(path: &Path) -> Result<Vec<ErrorReport>, ForensicError> {
    let mut reports = Vec::new();

    if !path.exists() {
        return Ok(reports);
    }

    if let Ok(entries) = strata_fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();

            if entry_path.is_dir() {
                if let Ok(report) = parse_report_folder(&entry_path) {
                    if !report.report_id.is_empty() {
                        reports.push(report);
                    }
                }
            } else if entry_path
                .extension()
                .map(|e| e == "mdmp" || e == "hdmp")
                .unwrap_or(false)
            {
                let report_id = entry_path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();

                let metadata = strata_fs::metadata(&entry_path).ok();
                let date = metadata.and_then(|m| m.modified().ok()).map(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64
                });

                reports.push(ErrorReport {
                    report_id,
                    app_name: None,
                    app_version: None,
                    description: None,
                    event_type: None,
                    date,
                    status: Some("Pending".to_string()),
                    bucket: None,
                    files: vec![entry_path.display().to_string()],
                });
            }
        }
    }

    Ok(reports)
}

fn parse_report_folder(path: &Path) -> Result<ErrorReport, ForensicError> {
    let report_id = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut report = ErrorReport {
        report_id,
        app_name: None,
        app_version: None,
        description: None,
        event_type: None,
        date: None,
        status: None,
        bucket: None,
        files: Vec::new(),
    };

    if let Ok(entries) = strata_fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let file_name = entry_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            if entry_path.is_file() {
                if file_name.ends_with(".mdmp") || file_name.ends_with(".hdmp") {
                    report.files.push(entry_path.display().to_string());
                } else if file_name == "WERInternalMetadata.xml" || file_name == "Report.wer" {
                    if let Ok(content) = read_text_prefix(&entry_path, DEFAULT_TEXT_MAX_BYTES) {
                        parse_wer_file(&content, &mut report);
                    }
                } else if file_name == "container.xml" {
                    if let Ok(content) = read_text_prefix(&entry_path, DEFAULT_TEXT_MAX_BYTES) {
                        parse_container_xml(&content, &mut report);
                    }
                }
            }
        }
    }

    if report.date.is_none() {
        if let Ok(meta) = strata_fs::metadata(path) {
            if let Ok(modified) = meta.modified() {
                report.date = Some(
                    modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                );
            }
        }
    }

    Ok(report)
}

fn parse_wer_file(content: &str, report: &mut ErrorReport) {
    for line in content.lines() {
        let line = line.trim();

        if line.starts_with("AppName=") {
            report.app_name = Some(line.trim_start_matches("AppName=").to_string());
        } else if line.starts_with("AppVersion=") {
            report.app_version = Some(line.trim_start_matches("AppVersion=").to_string());
        } else if line.starts_with("EventType=") {
            report.event_type = Some(line.trim_start_matches("EventType=").to_string());
        } else if line.starts_with("ResponseType=") {
            report.status = Some(line.trim_start_matches("ResponseType=").to_string());
        } else if line.starts_with("Bucket=") {
            report.bucket = Some(line.trim_start_matches("Bucket=").to_string());
        }
    }
}

fn parse_container_xml(content: &str, report: &mut ErrorReport) {
    for line in content.lines() {
        let line = line.trim();

        if line.contains("<ApplicationName>") {
            if let Some(start) = line.find("<ApplicationName>") {
                let value_start = start + 17;
                if let Some(end) = line[value_start..].find("</ApplicationName>") {
                    report.app_name = Some(line[value_start..value_start + end].to_string());
                }
            }
        } else if line.contains("<ApplicationVersion>") {
            if let Some(start) = line.find("<ApplicationVersion>") {
                let value_start = start + 19;
                if let Some(end) = line[value_start..].find("</ApplicationVersion>") {
                    report.app_version = Some(line[value_start..value_start + end].to_string());
                }
            }
        } else if line.contains("<EventType>") {
            if let Some(start) = line.find("<EventType>") {
                let value_start = start + 11;
                if let Some(end) = line[value_start..].find("</EventType>") {
                    report.event_type = Some(line[value_start..value_start + end].to_string());
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CrashPadReport {
    pub report_id: String,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    pub crash_time: Option<i64>,
    pub crash_type: Option<String>,
    pub signature: Option<String>,
    pub threads: Vec<CrashThread>,
    pub modules: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CrashThread {
    pub thread_id: u32,
    pub crashed: bool,
    pub stack_frames: Vec<String>,
}

pub fn parse_crashpad_reports(base_path: &Path) -> Result<Vec<CrashPadReport>, ForensicError> {
    let mut reports = Vec::new();

    let crashpad_path = base_path.join("AppData").join("Local").join("CrashDumps");

    if !crashpad_path.exists() {
        return Ok(reports);
    }

    if let Ok(entries) = strata_fs::read_dir(&crashpad_path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();

            if entry_path.extension().map(|e| e == "dmp").unwrap_or(false) {
                if let Ok(report) = parse_minidump(&entry_path) {
                    reports.push(report);
                }
            }
        }
    }

    Ok(reports)
}

fn parse_minidump(path: &Path) -> Result<CrashPadReport, ForensicError> {
    let data = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)?;

    let report_id = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut report = CrashPadReport {
        report_id,
        product_name: None,
        product_version: None,
        crash_time: None,
        crash_type: None,
        signature: None,
        threads: Vec::new(),
        modules: Vec::new(),
    };

    if data.len() < 8 {
        return Ok(report);
    }

    if data[0..4] == b"MDMP"[..] && data.len() > 24 {
        let dump_time = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        if dump_time > 0 {
            report.crash_time = Some(dump_time as i64);
        }
    }

    if let Ok(meta) = strata_fs::metadata(path) {
        if let Ok(modified) = meta.modified() {
            if report.crash_time.is_none() {
                report.crash_time = Some(
                    modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                );
            }
        }
    }

    Ok(report)
}

pub fn scan_all_error_reports() -> Result<Vec<ErrorReport>, ForensicError> {
    let mut all_reports = Vec::new();

    let user_dirs = [
        std::env::var("LOCALAPPDATA").ok(),
        std::env::var("APPDATA").ok(),
    ];

    for user_dir in user_dirs.into_iter().flatten() {
        let reports_path = Path::new(&user_dir)
            .join("Microsoft")
            .join("Windows")
            .join("WER");

        if reports_path.exists() {
            if let Ok(reports) = parse_error_reports(&reports_path) {
                all_reports.extend(reports);
            }
        }

        let temp_reports = Path::new(&user_dir).join("Temp").join("WER");
        if temp_reports.exists() {
            if let Ok(reports) = parse_error_reports(&temp_reports) {
                all_reports.extend(reports);
            }
        }
    }

    let system_reports = Path::new("C:\\ProgramData")
        .join("Microsoft")
        .join("Windows")
        .join("WER");
    if system_reports.exists() {
        if let Ok(reports) = parse_error_reports(&system_reports) {
            all_reports.extend(reports);
        }
    }

    Ok(all_reports)
}

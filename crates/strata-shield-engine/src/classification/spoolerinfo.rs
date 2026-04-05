use std::path::{Path, PathBuf};

use serde_json::Value;

use super::reg_export::default_reg_path;
use super::regservice;

pub fn get_windows_spooler() -> SpoolerInfo {
    let services_path = default_reg_path("services.reg");
    let jobs_path = PathBuf::from("artifacts")
        .join("spooler")
        .join("print_jobs.json");
    get_windows_spooler_from_sources(&services_path, &jobs_path)
}

pub fn get_windows_spooler_from_sources(services_reg_path: &Path, jobs_path: &Path) -> SpoolerInfo {
    let services = regservice::get_services_config_from_reg(services_reg_path);
    let spooler_service = services
        .into_iter()
        .find(|service| service.name.eq_ignore_ascii_case("Spooler"));

    let jobs = parse_print_jobs_count(jobs_path);

    if let Some(service) = spooler_service {
        let mut reasons = Vec::new();
        let running = matches!(service.start_type.as_str(), "Automatic" | "Boot" | "System");

        if !is_system_spooler_path(&service.path) && !service.path.trim().is_empty() {
            reasons.push("spooler_binary_outside_system32".to_string());
        }

        SpoolerInfo {
            running,
            jobs: jobs as u32,
            start_type: service.start_type,
            image_path: service.path,
            suspicious: !reasons.is_empty(),
            reasons,
        }
    } else {
        SpoolerInfo {
            running: false,
            jobs: jobs as u32,
            start_type: "Unknown".to_string(),
            image_path: String::new(),
            suspicious: false,
            reasons: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpoolerInfo {
    pub running: bool,
    pub jobs: u32,
    pub start_type: String,
    pub image_path: String,
    pub suspicious: bool,
    pub reasons: Vec<String>,
}

fn parse_print_jobs_count(path: &Path) -> usize {
    let Ok(data) = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) else {
        return 0;
    };

    let Ok(parsed) = serde_json::from_slice::<Value>(&data) else {
        return 0;
    };

    if let Some(items) = parsed.as_array() {
        return items.len();
    }

    if parsed.is_object() {
        return 1;
    }

    0
}

fn is_system_spooler_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    lower.contains("\\windows\\system32\\spoolsv.exe")
        || lower.contains("%systemroot%\\system32\\spoolsv.exe")
        || lower.contains("\\systemroot\\system32\\spoolsv.exe")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_spooler_state_and_job_count() {
        let dir = tempfile::tempdir().expect("temp dir");
        let services = dir.path().join("services.reg");
        let jobs = dir.path().join("print_jobs.json");

        strata_fs::write(
            &services,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler]
"DisplayName"="Print Spooler"
"ImagePath"="%SystemRoot%\\System32\\spoolsv.exe"
"Start"=dword:00000002
"Type"=dword:00000010
"#,
        )
        .expect("write services");

        strata_fs::write(
            &jobs,
            r#"[{"job_id":1,"document":"report.docx"},{"job_id":2,"document":"invoice.pdf"}]"#,
        )
        .expect("write jobs");

        let info = get_windows_spooler_from_sources(&services, &jobs);
        assert!(info.running);
        assert_eq!(info.jobs, 2);
        assert!(!info.suspicious);
    }

    #[test]
    fn flags_non_standard_spooler_binary_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let services = dir.path().join("services.reg");
        let jobs = dir.path().join("print_jobs.json");

        strata_fs::write(
            &services,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler]
"ImagePath"="C:\\Users\\Public\\spoolsv.exe"
"Start"=dword:00000002
"Type"=dword:00000010
"#,
        )
        .expect("write services");
        strata_fs::write(&jobs, "[]").expect("write jobs");

        let info = get_windows_spooler_from_sources(&services, &jobs);
        assert!(info.suspicious);
        assert!(info
            .reasons
            .iter()
            .any(|reason| reason == "spooler_binary_outside_system32"));
    }
}

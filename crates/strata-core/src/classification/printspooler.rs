use crate::errors::ForensicError;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PrintJob {
    pub job_id: u32,
    pub document_name: Option<String>,
    pub printer_name: Option<String>,
    pub submitted_time: Option<i64>,
    pub owner: Option<String>,
    pub pages: Option<u32>,
    pub bytes: Option<u64>,
    pub status: PrintJobStatus,
}

#[derive(Debug, Clone)]
pub enum PrintJobStatus {
    Printing,
    Paused,
    Deleted,
    Error,
    Unknown,
}

pub fn parse_print_jobs(base_path: &Path) -> Result<Vec<PrintJob>, ForensicError> {
    let mut jobs = Vec::new();

    let control_set = find_current_control_set(base_path)?;

    let print_jobs_path = base_path
        .join("SYSTEM")
        .join(&control_set)
        .join("Services")
        .join("Spooler")
        .join("PRINTERS");

    if !print_jobs_path.exists() {
        return Ok(jobs);
    }

    if let Ok(entries) = strata_fs::read_dir(&print_jobs_path) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let mut job = PrintJob {
                    job_id: 0,
                    document_name: None,
                    printer_name: None,
                    submitted_time: None,
                    owner: None,
                    pages: None,
                    bytes: None,
                    status: PrintJobStatus::Unknown,
                };

                let job_id = entry.file_name().to_string_lossy().to_string();
                if let Ok(id) = job_id.parse::<u32>() {
                    job.job_id = id;
                }

                if let Ok(sub_entries) = strata_fs::read_dir(entry.path()) {
                    for sub_entry in sub_entries.flatten() {
                        let file_name = sub_entry.file_name().to_string_lossy().to_string();
                        let sub_path = sub_entry.path();
                        if let Ok(data) = super::scalpel::read_prefix(
                            &sub_path,
                            super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                        ) {
                            match file_name.as_str() {
                                "Document" => job.document_name = extract_registry_string(&data),
                                "PrinterName" => job.printer_name = extract_registry_string(&data),
                                "Owner" => job.owner = extract_registry_string(&data),
                                "SubmittedTime" => {
                                    if data.len() >= 8 {
                                        let ts = u64::from_le_bytes([
                                            data[0], data[1], data[2], data[3], data[4], data[5],
                                            data[6], data[7],
                                        ]);
                                        job.submitted_time =
                                            Some((ts / 10_000_000 - 11644473600) as i64);
                                    }
                                }
                                "Size" => {
                                    if data.len() >= 4 {
                                        job.bytes = Some(u32::from_le_bytes([
                                            data[0], data[1], data[2], data[3],
                                        ])
                                            as u64);
                                    }
                                }
                                "PagesPrinted" | "Pages" => {
                                    if data.len() >= 4 {
                                        job.pages = Some(u32::from_le_bytes([
                                            data[0], data[1], data[2], data[3],
                                        ]));
                                    }
                                }
                                "Status" => {
                                    if let Some(status_str) = extract_registry_string(&data) {
                                        job.status = parse_print_status(&status_str);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }

                jobs.push(job);
            }
        }
    }

    jobs.sort_by(|a, b| b.submitted_time.cmp(&a.submitted_time));
    Ok(jobs)
}

fn find_current_control_set(base_path: &Path) -> Result<String, ForensicError> {
    let select_path = base_path.join("SYSTEM").join("Select");

    if !select_path.exists() {
        return Ok("ControlSet001".to_string());
    }

    if let Ok(entries) = strata_fs::read_dir(&select_path) {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name == "Current" {
                if let Ok(data) = super::scalpel::read_prefix(
                    &entry.path(),
                    super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                ) {
                    if let Some(value) = extract_registry_string(&data) {
                        if let Ok(num) = value.parse::<u32>() {
                            return Ok(format!("ControlSet{:03}", num));
                        }
                    }
                }
            }
        }
    }

    Ok("ControlSet001".to_string())
}

fn extract_registry_string(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    if data.len() >= 4 && &data[0..4] == b"\x01\x00\x00\x00" {
        let offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if data.len() > offset + 2 {
            let end = data[offset..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(data.len() - offset);
            let s = String::from_utf8_lossy(&data[offset..offset + end]).to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        }
    } else {
        let s = String::from_utf8_lossy(data)
            .trim_end_matches('\0')
            .to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

fn parse_print_status(status: &str) -> PrintJobStatus {
    match status.to_lowercase().as_str() {
        "printing" => PrintJobStatus::Printing,
        "paused" | "hold" => PrintJobStatus::Paused,
        "deleted" | "deleting" => PrintJobStatus::Deleted,
        "error" | "failed" => PrintJobStatus::Error,
        _ => PrintJobStatus::Unknown,
    }
}

#[derive(Debug, Clone)]
pub struct InstalledPrinter {
    pub name: String,
    pub port_name: Option<String>,
    pub driver_name: Option<String>,
    pub server_name: Option<String>,
    pub url: Option<String>,
}

pub fn parse_installed_printers(base_path: &Path) -> Result<Vec<InstalledPrinter>, ForensicError> {
    let mut printers = Vec::new();

    let printers_path = base_path
        .join("SOFTWARE")
        .join("Microsoft")
        .join("Windows NT")
        .join("CurrentVersion")
        .join("Print")
        .join("Printers");

    if !printers_path.exists() {
        return Ok(printers);
    }

    if let Ok(entries) = strata_fs::read_dir(&printers_path) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let mut printer = InstalledPrinter {
                    name: entry.file_name().to_string_lossy().to_string(),
                    port_name: None,
                    driver_name: None,
                    server_name: None,
                    url: None,
                };

                if let Ok(sub_entries) = strata_fs::read_dir(entry.path()) {
                    for sub_entry in sub_entries.flatten() {
                        let file_name = sub_entry.file_name().to_string_lossy().to_string();
                        let sub_path = sub_entry.path();
                        if let Ok(data) = super::scalpel::read_prefix(
                            &sub_path,
                            super::scalpel::DEFAULT_BINARY_MAX_BYTES,
                        ) {
                            match file_name.as_str() {
                                "Port" | "PortName" => {
                                    printer.port_name = extract_registry_string(&data)
                                }
                                "Driver" | "DriverName" => {
                                    printer.driver_name = extract_registry_string(&data)
                                }
                                "Server" | "ServerName" => {
                                    printer.server_name = extract_registry_string(&data)
                                }
                                "URL" => printer.url = extract_registry_string(&data),
                                _ => {}
                            }
                        }
                    }
                }

                printers.push(printer);
            }
        }
    }

    Ok(printers)
}

//! Evidence Drive Enforcement — hard-blocks system drives.
//! Forensic evidence MUST be stored on a dedicated drive.
//! This is a court-defensibility feature, not a preference.

use crate::state::{colors::*, AppState};
use std::path::{Path, PathBuf};

// ─── Drive classification ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum DriveType {
    System,
    Boot,
    External,
    SecondaryInternal,
    NetworkShare,
}

#[derive(Debug, Clone)]
pub struct DriveInfo {
    pub path: PathBuf,
    pub label: String,
    #[allow(dead_code)]
    pub drive_type: DriveType,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub is_permitted: bool,
    pub block_reason: Option<String>,
}

/// Minimum free space required on evidence drive (10 GB).
const MIN_FREE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Check if a path is on a system drive (BLOCKED for evidence storage).
pub fn is_system_drive(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    #[cfg(target_os = "macos")]
    {
        // On macOS, check if same device as root
        if let (Ok(root_meta), Ok(path_meta)) = (
            std::fs::metadata("/"),
            std::fs::metadata(path),
        ) {
            use std::os::unix::fs::MetadataExt;
            if root_meta.dev() == path_meta.dev() {
                return true;
            }
        }
        // Also block well-known system paths
        let blocked = ["/System", "/Library", "/Users", "/private", "/var", "/usr", "/etc", "/bin", "/sbin"];
        for b in &blocked {
            if path_str.starts_with(b) {
                return true;
            }
        }
        // Block home directory
        if let Ok(home) = std::env::var("HOME") {
            if path_str.starts_with(&home) {
                return true;
            }
        }
        false
    }

    #[cfg(target_os = "windows")]
    {
        let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        if path_str.to_uppercase().starts_with(&sys_drive.to_uppercase()) {
            return true;
        }
        let blocked = ["C:\\", "C:\\Windows", "C:\\Program Files", "C:\\Users"];
        for b in &blocked {
            if path_str.to_uppercase().starts_with(&b.to_uppercase()) {
                return true;
            }
        }
        false
    }

    #[cfg(target_os = "linux")]
    {
        if let (Ok(root_meta), Ok(path_meta)) = (
            std::fs::metadata("/"),
            std::fs::metadata(path),
        ) {
            use std::os::unix::fs::MetadataExt;
            if root_meta.dev() == path_meta.dev() {
                return true;
            }
        }
        let blocked = ["/home", "/root", "/var", "/usr", "/etc", "/bin", "/sbin", "/tmp"];
        for b in &blocked {
            if path_str.starts_with(b) {
                return true;
            }
        }
        false
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        false
    }
}

/// Enumerate available drives/volumes.
pub fn enumerate_drives() -> Vec<DriveInfo> {
    let mut drives = Vec::new();

    #[cfg(target_os = "macos")]
    {
        // macOS: check /Volumes/*
        if let Ok(entries) = std::fs::read_dir("/Volumes") {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let label = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                let is_system = is_system_drive(&path);
                let (total, free) = disk_space(&path);

                let drive_type = if is_system {
                    DriveType::System
                } else {
                    DriveType::External
                };

                let block_reason = if is_system {
                    Some("System volume — not permitted for evidence storage".to_string())
                } else if free < MIN_FREE_BYTES {
                    Some(format!(
                        "Insufficient space: {} GB free (minimum 10 GB)",
                        free / (1024 * 1024 * 1024)
                    ))
                } else {
                    None
                };

                let is_permitted = !is_system && free >= MIN_FREE_BYTES;

                drives.push(DriveInfo {
                    path,
                    label,
                    drive_type,
                    total_bytes: total,
                    free_bytes: free,
                    is_permitted,
                    block_reason,
                });
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows: check drive letters A-Z
        for letter in b'A'..=b'Z' {
            let drive_path = format!("{}:\\", letter as char);
            let path = PathBuf::from(&drive_path);
            if !path.exists() {
                continue;
            }

            let is_system = is_system_drive(&path);
            let (total, free) = disk_space(&path);
            let label = format!("{}:", letter as char);

            let drive_type = if is_system {
                DriveType::System
            } else {
                DriveType::SecondaryInternal
            };

            let block_reason = if is_system {
                Some("System drive — not permitted for evidence storage".to_string())
            } else if free < MIN_FREE_BYTES {
                Some(format!(
                    "Insufficient space: {} GB free (minimum 10 GB)",
                    free / (1024 * 1024 * 1024)
                ))
            } else {
                None
            };

            let is_permitted = !is_system && free >= MIN_FREE_BYTES;

            drives.push(DriveInfo {
                path,
                label,
                drive_type,
                total_bytes: total,
                free_bytes: free,
                is_permitted,
                block_reason,
            });
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Linux: check /mnt/* and /media/*/*
        for mount_root in &["/mnt", "/media"] {
            if let Ok(entries) = std::fs::read_dir(mount_root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_dir() {
                        continue;
                    }
                    // /media/<user>/<device> structure
                    if *mount_root == "/media" {
                        if let Ok(sub_entries) = std::fs::read_dir(&path) {
                            for sub in sub_entries.flatten() {
                                let sub_path = sub.path();
                                if sub_path.is_dir() {
                                    add_linux_drive(&mut drives, sub_path);
                                }
                            }
                        }
                    } else {
                        add_linux_drive(&mut drives, path);
                    }
                }
            }
        }
    }

    drives
}

#[cfg(target_os = "linux")]
fn add_linux_drive(drives: &mut Vec<DriveInfo>, path: PathBuf) {
    let label = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let is_system = is_system_drive(&path);
    let (total, free) = disk_space(&path);
    let is_permitted = !is_system && free >= MIN_FREE_BYTES;

    drives.push(DriveInfo {
        path,
        label,
        drive_type: if is_system { DriveType::System } else { DriveType::External },
        total_bytes: total,
        free_bytes: free,
        is_permitted,
        block_reason: if is_system {
            Some("System partition — not permitted".to_string())
        } else if free < MIN_FREE_BYTES {
            Some("Insufficient free space".to_string())
        } else {
            None
        },
    });
}

fn disk_space(path: &Path) -> (u64, u64) {
    // Use `df` on Unix to get disk space
    #[cfg(unix)]
    {
        let output = std::process::Command::new("df")
            .arg("-k")
            .arg(path.as_os_str())
            .output();

        if let Ok(output) = output {
            let text = String::from_utf8_lossy(&output.stdout);
            // df -k output: Filesystem 1024-blocks Used Available Use% Mounted-on
            if let Some(line) = text.lines().nth(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let total_kb = parts[1].parse::<u64>().unwrap_or(0);
                    let avail_kb = parts[3].parse::<u64>().unwrap_or(0);
                    return (total_kb * 1024, avail_kb * 1024);
                }
            }
        }
        (0, 0)
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        (0, 0)
    }
}

/// Create the evidence directory structure on the selected drive.
pub fn create_evidence_structure(base_path: &Path, case_number: &str) -> Result<PathBuf, String> {
    let case_dir = base_path.join("Cases").join(case_number);
    let subdirs = ["evidence", "exports", "carved", "bookmarks", "timeline", "audit"];

    std::fs::create_dir_all(&case_dir).map_err(|e| format!("Failed to create case directory: {}", e))?;

    for sub in &subdirs {
        let sub_path = case_dir.join(sub);
        std::fs::create_dir_all(&sub_path)
            .map_err(|e| format!("Failed to create {}: {}", sub, e))?;
    }

    Ok(case_dir)
}

// ─── Evidence Drive Selection UI ─────────────────────────────────────────────

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    if !state.show_drive_selection {
        return;
    }

    egui::Window::new("Select Evidence Drive")
        .collapsible(false)
        .resizable(false)
        .default_width(520.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.label(
                egui::RichText::new("EVIDENCE DRIVE SELECTION")
                    .color(ACCENT)
                    .size(11.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Evidence must be stored on a dedicated drive.\nSystem and boot drives are not permitted.",
                )
                .color(TEXT_SEC)
                .size(9.5),
            );
            ui.add_space(8.0);

            // Refresh drives
            if state.available_drives.is_empty() || ui.button("Refresh Drives").clicked() {
                state.available_drives = enumerate_drives();
            }

            ui.separator();

            // Drive list
            for (idx, drive) in state.available_drives.iter().enumerate() {
                let icon = if drive.is_permitted { "✅" } else { "❌" };
                let free_gb = drive.free_bytes / (1024 * 1024 * 1024);
                let total_gb = drive.total_bytes / (1024 * 1024 * 1024);

                let label = format!(
                    "{} {} — {}GB / {}GB free",
                    icon, drive.label, free_gb, total_gb,
                );

                let is_selected = state.selected_drive_index == Some(idx);

                if drive.is_permitted {
                    if ui
                        .selectable_label(is_selected, egui::RichText::new(&label).color(TEXT_PRI).size(10.0))
                        .clicked()
                    {
                        state.selected_drive_index = Some(idx);
                        state.drive_block_message.clear();
                    }
                } else {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&label).color(TEXT_MUTED).size(10.0));
                        if let Some(ref reason) = drive.block_reason {
                            ui.label(egui::RichText::new(reason).color(DANGER).size(8.0));
                        }
                    });
                }
            }

            if state.available_drives.is_empty() {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("No drives detected. Connect an external evidence drive and click Refresh.")
                        .color(AMBER)
                        .size(9.5),
                );
            }

            // Evidence path preview
            if let Some(idx) = state.selected_drive_index {
                if let Some(drive) = state.available_drives.get(idx) {
                    ui.add_space(8.0);
                    let case_num = if state.case_number.is_empty() {
                        "new-case"
                    } else {
                        &state.case_number
                    };
                    let evidence_path = drive.path.join("Cases").join(case_num);
                    ui.label(
                        egui::RichText::new(format!("Evidence Path: {}", evidence_path.display()))
                            .color(ACCENT)
                            .size(9.0)
                            .monospace(),
                    );
                }
            }

            // Block message
            if !state.drive_block_message.is_empty() {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(&state.drive_block_message)
                        .color(DANGER)
                        .size(9.0),
                );
            }

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                // Only allow back if a drive was already selected (re-selection)
                if state.evidence_drive_path.is_some() && ui.button("Back").clicked() {
                    state.show_drive_selection = false;
                }

                let can_proceed = state
                    .selected_drive_index
                    .and_then(|i| state.available_drives.get(i))
                    .map(|d| d.is_permitted)
                    .unwrap_or(false);

                ui.add_enabled_ui(can_proceed, |ui| {
                    if ui
                        .button(
                            egui::RichText::new("Begin Examination →")
                                .color(ACCENT)
                                .strong(),
                        )
                        .clicked()
                    {
                        // Clone drive info to avoid borrow conflict
                        let drive_info = state
                            .selected_drive_index
                            .and_then(|i| state.available_drives.get(i))
                            .cloned();

                        if let Some(drive) = drive_info {
                            let case_num = if state.case_number.is_empty() {
                                "new-case".to_string()
                            } else {
                                state.case_number.clone()
                            };

                            match create_evidence_structure(&drive.path, &case_num) {
                                Ok(case_dir) => {
                                    state.evidence_drive_path = Some(drive.path.clone());
                                    state.evidence_case_dir = Some(case_dir.clone());
                                    state.show_drive_selection = false;
                                    // Auto-open evidence dialog after drive selection
                                    state.open_ev_dlg.open = true;
                                    state.log_action(
                                        "EVIDENCE_DRIVE_SELECTED",
                                        &format!(
                                            "drive={} path={}",
                                            drive.label,
                                            case_dir.display()
                                        ),
                                    );
                                    state.status = format!(
                                        "Evidence drive: {} — Case directory created",
                                        drive.label
                                    );
                                }
                                Err(e) => {
                                    state.drive_block_message =
                                        format!("Failed to create evidence directory: {}", e);
                                }
                            }
                        }
                    }
                });
            });
        });
}

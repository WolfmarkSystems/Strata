// Extracted from main.rs — run_execution_correlation_command
// TODO: Convert to clap derive args in a future pass

use crate::*;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "execution-correlation",
    about = "Correlate executable runs across all artifacts"
)]
pub struct ExecutionCorrelationArgs {
    #[arg(long, alias = "prefetch-input")]
    pub prefetch_dir: Option<PathBuf>,

    #[arg(long, alias = "jumplist-input")]
    pub jumplist_path: Option<PathBuf>,

    #[arg(long)]
    pub shortcuts_base: Option<PathBuf>,

    #[arg(long)]
    pub lnk_input: Option<PathBuf>,

    #[arg(long)]
    pub browser_input: Option<PathBuf>,

    #[arg(long)]
    pub rdp_input: Option<PathBuf>,

    #[arg(long)]
    pub usb_input: Option<PathBuf>,

    #[arg(long)]
    pub restore_shadow_input: Option<PathBuf>,

    #[arg(long)]
    pub user_activity_input: Option<PathBuf>,

    #[arg(long, alias = "timeline-qa-input")]
    pub timeline_correlation_input: Option<PathBuf>,

    #[arg(long)]
    pub srum_input: Option<PathBuf>,

    #[arg(long)]
    pub evtx_security_input: Option<PathBuf>,

    #[arg(long)]
    pub evtx_sysmon_input: Option<PathBuf>,

    #[arg(long)]
    pub powershell_history: Option<PathBuf>,

    #[arg(long)]
    pub powershell_script_log: Option<PathBuf>,

    #[arg(long)]
    pub powershell_events: Option<PathBuf>,

    #[arg(long)]
    pub runmru_reg: Option<PathBuf>,

    #[arg(long)]
    pub opensave_reg: Option<PathBuf>,

    #[arg(long)]
    pub userassist_reg: Option<PathBuf>,

    #[arg(long)]
    pub recentdocs_reg: Option<PathBuf>,

    #[arg(long)]
    pub autorun_reg: Option<PathBuf>,

    #[arg(long)]
    pub bam_reg: Option<PathBuf>,

    #[arg(long)]
    pub amcache_reg: Option<PathBuf>,

    #[arg(long, alias = "appcompat-reg")]
    pub shimcache_reg: Option<PathBuf>,

    #[arg(long)]
    pub services_reg: Option<PathBuf>,

    #[arg(long)]
    pub tasks_root: Option<PathBuf>,

    #[arg(long)]
    pub wmi_persist_input: Option<PathBuf>,

    #[arg(long)]
    pub wmi_traces_input: Option<PathBuf>,

    #[arg(long)]
    pub wmi_instances_input: Option<PathBuf>,

    #[arg(long)]
    pub mft_input: Option<PathBuf>,

    #[arg(long)]
    pub usn_input: Option<PathBuf>,

    #[arg(long)]
    pub logfile_input: Option<PathBuf>,

    #[arg(long)]
    pub recycle_input: Option<PathBuf>,

    #[arg(long)]
    pub defender_input: Option<PathBuf>,

    #[arg(short, long, default_value_t = crate::EXECUTION_CORRELATION_DEFAULT_LIMIT)]
    pub limit: usize,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long)]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: ExecutionCorrelationArgs, command_name: &str, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let limit = args.limit.clamp(1, crate::EXECUTION_CORRELATION_MAX_LIMIT);
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let prefetch_dir = args
        .prefetch_dir
        .or(std::env::var("FORENSIC_PREFETCH_DIR")
            .ok()
            .map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("C:\\Windows\\Prefetch"));
    let jumplist_path = args
        .jumplist_path
        .or(std::env::var("FORENSIC_JUMPLIST_PATH")
            .ok()
            .map(PathBuf::from))
        .unwrap_or_else(crate::default_jumplist_path);
    let shortcuts_base = args
        .shortcuts_base
        .or(std::env::var("FORENSIC_SHORTCUTS_BASE")
            .ok()
            .map(PathBuf::from))
        .unwrap_or_else(crate::default_shortcuts_base);
    let lnk_input = args
        .lnk_input
        .or(std::env::var("FORENSIC_LNK_PATH").ok().map(PathBuf::from));
    let browser_input = args.browser_input.or(std::env::var("FORENSIC_BROWSER_PATH")
        .ok()
        .map(PathBuf::from));
    let rdp_input = args
        .rdp_input
        .or(std::env::var("FORENSIC_RDP_PATH").ok().map(PathBuf::from));
    let usb_input = args
        .usb_input
        .or(std::env::var("FORENSIC_USB_PATH").ok().map(PathBuf::from));
    let restore_shadow_input =
        args.restore_shadow_input
            .or(std::env::var("FORENSIC_RESTORE_SHADOW_PATH")
                .ok()
                .map(PathBuf::from));
    let user_activity_input =
        args.user_activity_input
            .or(std::env::var("FORENSIC_USER_ACTIVITY_MRU_PATH")
                .ok()
                .map(PathBuf::from));
    let timeline_correlation_input =
        args.timeline_correlation_input
            .or(std::env::var("FORENSIC_TIMELINE_CORRELATION_QA_PATH")
                .ok()
                .map(PathBuf::from));
    let srum_input = args
        .srum_input
        .or(std::env::var("FORENSIC_SRUM_PATH").ok().map(PathBuf::from));
    let evtx_security_input =
        args.evtx_security_input
            .or(std::env::var("FORENSIC_EVTX_SECURITY_PATH")
                .ok()
                .map(PathBuf::from));
    let evtx_sysmon_input = args
        .evtx_sysmon_input
        .or(std::env::var("FORENSIC_EVTX_SYSMON_PATH")
            .ok()
            .map(PathBuf::from));
    let powershell_history_input =
        args.powershell_history
            .or(std::env::var("FORENSIC_POWERSHELL_HISTORY")
                .ok()
                .map(PathBuf::from));
    let powershell_script_log_input =
        args.powershell_script_log
            .or(std::env::var("FORENSIC_POWERSHELL_SCRIPT_LOG")
                .ok()
                .map(PathBuf::from));
    let powershell_events_input =
        args.powershell_events
            .or(std::env::var("FORENSIC_POWERSHELL_EVENTS")
                .ok()
                .map(PathBuf::from));
    let runmru_reg_input = args.runmru_reg.or(std::env::var("FORENSIC_RUNMRU_PATH")
        .ok()
        .map(PathBuf::from));
    let opensave_reg_input = args.opensave_reg.or(std::env::var("FORENSIC_OPENSAVE_PATH")
        .ok()
        .map(PathBuf::from));
    let userassist_reg_input = args
        .userassist_reg
        .or(std::env::var("FORENSIC_USERASSIST_PATH")
            .ok()
            .map(PathBuf::from));
    let recentdocs_reg_input = args
        .recentdocs_reg
        .or(std::env::var("FORENSIC_RECENTDOCS_PATH")
            .ok()
            .map(PathBuf::from));
    let autorun_reg_input = args.autorun_reg.or(std::env::var("FORENSIC_AUTORUN_PATH")
        .ok()
        .map(PathBuf::from));
    let bam_reg_input = args
        .bam_reg
        .or(std::env::var("FORENSIC_BAM_PATH").ok().map(PathBuf::from));
    let amcache_reg_input = args.amcache_reg.or(std::env::var("FORENSIC_AMCACHE_PATH")
        .ok()
        .map(PathBuf::from));
    let shimcache_reg_input = args
        .shimcache_reg
        .or(std::env::var("FORENSIC_SHIMCACHE_PATH")
            .ok()
            .map(PathBuf::from));
    let services_reg_input = args.services_reg.or(std::env::var("FORENSIC_SERVICES_PATH")
        .ok()
        .map(PathBuf::from));
    let tasks_root_input = args
        .tasks_root
        .or(std::env::var("FORENSIC_TASKS_ROOT").ok().map(PathBuf::from));
    let wmi_persist_input = args
        .wmi_persist_input
        .or(std::env::var("FORENSIC_WMI_PERSIST_PATH")
            .ok()
            .map(PathBuf::from));
    let wmi_traces_input = args
        .wmi_traces_input
        .or(std::env::var("FORENSIC_WMI_TRACES_PATH")
            .ok()
            .map(PathBuf::from));
    let wmi_instances_input =
        args.wmi_instances_input
            .or(std::env::var("FORENSIC_WMI_INSTANCES_PATH")
                .ok()
                .map(PathBuf::from));
    let mft_input = args
        .mft_input
        .or(std::env::var("FORENSIC_MFT_PATH").ok().map(PathBuf::from));
    let usn_input = args
        .usn_input
        .or(std::env::var("FORENSIC_USN_PATH").ok().map(PathBuf::from));
    let logfile_input = args.logfile_input.or(std::env::var("FORENSIC_LOGFILE_PATH")
        .ok()
        .map(PathBuf::from));
    let recycle_input = args
        .recycle_input
        .or(std::env::var("FORENSIC_RECYCLE_BIN_PATH")
            .ok()
            .map(PathBuf::from));
    let defender_input = args
        .defender_input
        .or(std::env::var("FORENSIC_DEFENDER_ARTIFACTS_PATH")
            .ok()
            .map(PathBuf::from));

    let mut warnings: Vec<String> = Vec::new();
    let mut observed_users_by_executable: std::collections::HashMap<
        String,
        std::collections::BTreeSet<String>,
    > = std::collections::HashMap::new();
    let mut observed_devices_by_executable: std::collections::HashMap<
        String,
        std::collections::BTreeSet<String>,
    > = std::collections::HashMap::new();
    let mut observed_sids_by_executable: std::collections::HashMap<
        String,
        std::collections::BTreeSet<String>,
    > = std::collections::HashMap::new();

    let prefetch = if prefetch_dir.exists() {
        parse_prefetch_records_from_path(&prefetch_dir, limit)
    } else {
        warnings.push(format!(
            "Prefetch input not found: {}",
            prefetch_dir.display()
        ));
        Vec::new()
    };

    let jumplist = if jumplist_path.exists() {
        parse_jumplist_entries_from_path(&jumplist_path, limit)
    } else {
        warnings.push(format!(
            "Jump List source not found: {}",
            jumplist_path.display()
        ));
        Vec::new()
    };

    let shortcuts = if let Some(path) = lnk_input.as_ref() {
        if path.exists() {
            parse_lnk_shortcuts_from_path(path, limit)
                .into_iter()
                .map(
                    |row| forensic_engine::classification::shortcuts::ShortcutInfo {
                        path: row.path,
                        target: row.target_path,
                        arguments: row.arguments,
                        working_dir: row.working_directory,
                        created: row.created_unix,
                        modified: row.modified_unix,
                        description: row.description,
                    },
                )
                .collect::<Vec<_>>()
        } else {
            warnings.push(format!("LNK input not found: {}", path.display()));
            Vec::new()
        }
    } else if shortcuts_base.exists() {
        match collect_all_shortcuts(&shortcuts_base) {
            Ok(rows) => rows,
            Err(e) => {
                warnings.push(format!(
                    "Could not parse shortcut base {}: {}",
                    shortcuts_base.display(),
                    e
                ));
                Vec::new()
            }
        }
    } else {
        warnings.push(format!(
            "Shortcut base directory not found: {}",
            shortcuts_base.display()
        ));
        Vec::new()
    };

    let mut browser_rows_total = 0usize;
    let mut browser_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    if let Some(path) = browser_input.as_ref() {
        if path.exists() {
            let rows = parse_browser_records_from_path(path, limit);
            browser_rows_total = rows.len();
            for row in rows {
                let exe = row
                    .process_path
                    .as_deref()
                    .and_then(executable_name_from_hint)
                    .or_else(|| match row.browser.as_deref() {
                        Some("chrome") => Some("chrome.exe".to_string()),
                        Some("edge") => Some("msedge.exe".to_string()),
                        Some("firefox") => Some("firefox.exe".to_string()),
                        Some("safari") => Some("safari.exe".to_string()),
                        _ => None,
                    });
                let Some(exe_name) = exe else {
                    continue;
                };
                let ts = row.timestamp_unix;
                let entry = browser_by_executable.entry(exe_name).or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = match (entry.1, ts) {
                    (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
            }
        } else {
            warnings.push(format!("Browser input not found: {}", path.display()));
        }
    }

    let mut rdp_rows_total = 0usize;
    let mut rdp_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    if let Some(path) = rdp_input.as_ref() {
        if path.exists() {
            let rows = parse_rdp_records_from_path(path, limit);
            rdp_rows_total = rows.len();
            for row in rows {
                let exe = row
                    .process_path
                    .as_deref()
                    .and_then(executable_name_from_hint)
                    .or_else(|| Some("mstsc.exe".to_string()));
                let Some(exe_name) = exe else {
                    continue;
                };
                let ts = row
                    .timestamp_unix
                    .or(row.start_time_unix)
                    .or(row.end_time_unix);
                let entry = rdp_by_executable.entry(exe_name).or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = match (entry.1, ts) {
                    (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
            }
        } else {
            warnings.push(format!("RDP input not found: {}", path.display()));
        }
    }

    let mut usb_rows_total = 0usize;
    let mut usb_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    if let Some(path) = usb_input.as_ref() {
        if path.exists() {
            let rows = parse_usb_records_from_path(path, limit);
            usb_rows_total = rows.len();
            for row in rows {
                let exe = row
                    .source_path
                    .as_deref()
                    .and_then(executable_name_from_hint)
                    .or_else(|| {
                        row.friendly_name
                            .as_deref()
                            .and_then(executable_name_from_hint)
                    });
                let Some(exe_name) = exe else {
                    continue;
                };
                let ts = row
                    .timestamp_unix
                    .or(row.last_connected_unix)
                    .or(row.first_install_unix);
                let entry = usb_by_executable.entry(exe_name).or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = match (entry.1, ts) {
                    (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
            }
        } else {
            warnings.push(format!("USB input not found: {}", path.display()));
        }
    }

    let mut restore_shadow_rows_total = 0usize;
    let mut restore_shadow_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    if let Some(path) = restore_shadow_input.as_ref() {
        if path.exists() {
            let rows = parse_restore_shadow_records_from_path(path, limit);
            restore_shadow_rows_total = rows.len();
            for row in rows {
                let exe = row
                    .file_path
                    .as_deref()
                    .and_then(executable_name_from_hint)
                    .or_else(|| {
                        row.description
                            .as_deref()
                            .and_then(executable_name_from_command_text)
                    });
                let Some(exe_name) = exe else {
                    continue;
                };
                let ts = row.timestamp_unix;
                let entry = restore_shadow_by_executable
                    .entry(exe_name)
                    .or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = match (entry.1, ts) {
                    (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
            }
        } else {
            warnings.push(format!(
                "Restore/shadow input not found: {}",
                path.display()
            ));
        }
    }

    let mut user_activity_rows_total = 0usize;
    let mut user_activity_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    if let Some(path) = user_activity_input.as_ref() {
        if path.exists() {
            let rows = parse_user_activity_mru_records_from_path(path, limit);
            user_activity_rows_total = rows.len();
            for row in rows {
                let exe = row
                    .executable_name
                    .clone()
                    .or_else(|| {
                        row.command
                            .as_deref()
                            .and_then(executable_name_from_command_text)
                    })
                    .or_else(|| row.path.as_deref().and_then(executable_name_from_hint))
                    .or_else(|| {
                        row.program_name
                            .as_deref()
                            .and_then(executable_name_from_hint)
                    });
                let Some(exe_name) = exe else {
                    continue;
                };
                let ts = row.timestamp_unix;
                let entry = user_activity_by_executable
                    .entry(exe_name)
                    .or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = match (entry.1, ts) {
                    (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
            }
        } else {
            warnings.push(format!("User-activity input not found: {}", path.display()));
        }
    }

    let mut timeline_correlation_rows_total = 0usize;
    let mut timeline_correlation_by_executable: std::collections::HashMap<
        String,
        (u32, Option<i64>),
    > = std::collections::HashMap::new();
    if let Some(path) = timeline_correlation_input.as_ref() {
        if path.exists() {
            let rows = parse_timeline_correlation_qa_records_from_path(path, limit);
            timeline_correlation_rows_total = rows.len();
            for row in rows {
                let exe = row
                    .executable_name
                    .clone()
                    .or_else(|| {
                        row.command
                            .as_deref()
                            .and_then(executable_name_from_command_text)
                    })
                    .or_else(|| row.path.as_deref().and_then(executable_name_from_hint))
                    .or_else(|| {
                        row.summary
                            .as_deref()
                            .and_then(executable_name_from_command_text)
                    });
                let Some(exe_name) = exe else {
                    continue;
                };
                let ts = row.timestamp_unix;
                let entry = timeline_correlation_by_executable
                    .entry(exe_name)
                    .or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = match (entry.1, ts) {
                    (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
            }
        } else {
            warnings.push(format!(
                "Timeline-correlation input not found: {}",
                path.display()
            ));
        }
    }

    let mut srum_rows_total = 0usize;
    let mut srum_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    if let Some(path) = srum_input.as_ref() {
        if path.exists() {
            match strata_fs::read(path) {
                Ok(raw) => {
                    let parsed = parse_srum_records_with_metadata(&raw);
                    if !parsed.metadata.quality_flags.is_empty() {
                        warnings.push(format!(
                            "SRUM quality flags: {}",
                            parsed.metadata.quality_flags.join(",")
                        ));
                    }
                    srum_rows_total = parsed.records.len();
                    for row in parsed.records {
                        let exe = row
                            .exe_path
                            .as_deref()
                            .and_then(executable_name_from_hint)
                            .or_else(|| row.app_name.as_deref().and_then(executable_name_from_hint))
                            .or_else(|| row.app_id.as_deref().and_then(executable_name_from_hint));
                        let Some(exe_name) = exe else {
                            continue;
                        };
                        let ts = row.timestamp_unix;
                        let entry = srum_by_executable.entry(exe_name).or_insert((0, None));
                        entry.0 = entry.0.saturating_add(1);
                        entry.1 = match (entry.1, ts) {
                            (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                            (Some(a), None) => Some(a),
                            (None, Some(b)) => Some(b),
                            (None, None) => None,
                        };
                    }
                }
                Err(e) => warnings.push(format!(
                    "Could not read SRUM input {}: {}",
                    path.display(),
                    e
                )),
            }
        } else {
            warnings.push(format!("SRUM input not found: {}", path.display()));
        }
    }

    let mut evtx_security_rows_total = 0usize;
    let mut evtx_security_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    if let Some(path) = evtx_security_input.as_ref() {
        if path.exists() {
            match parse_security_log_with_metadata(path) {
                Ok(parsed) => {
                    if !parsed.metadata.quality_flags.is_empty() {
                        warnings.push(format!(
                            "EVTX security quality flags: {}",
                            parsed.metadata.quality_flags.join(",")
                        ));
                    }
                    evtx_security_rows_total = parsed.summary.entries.len();
                    for row in parsed.summary.entries {
                        let exe = row
                            .event_data
                            .get("NewProcessName")
                            .and_then(|v| executable_name_from_hint(v))
                            .or_else(|| {
                                row.event_data
                                    .get("ProcessName")
                                    .and_then(|v| executable_name_from_hint(v))
                            })
                            .or_else(|| {
                                row.event_data
                                    .get("Image")
                                    .and_then(|v| executable_name_from_hint(v))
                            })
                            .or_else(|| {
                                row.event_data
                                    .get("Process")
                                    .and_then(|v| executable_name_from_hint(v))
                            })
                            .or_else(|| {
                                row.event_data
                                    .get("ApplicationName")
                                    .and_then(|v| executable_name_from_hint(v))
                            });
                        let Some(exe_name) = exe else {
                            continue;
                        };
                        add_context_observation(
                            &mut observed_users_by_executable,
                            &exe_name,
                            row.user.as_deref(),
                        );
                        add_context_observation(
                            &mut observed_devices_by_executable,
                            &exe_name,
                            row.computer.as_deref(),
                        );
                        add_context_observations_from_event_data(
                            &mut observed_users_by_executable,
                            &exe_name,
                            &row.event_data,
                            &[
                                "SubjectUserName",
                                "TargetUserName",
                                "AccountName",
                                "UserName",
                            ],
                        );
                        add_context_observations_from_event_data(
                            &mut observed_sids_by_executable,
                            &exe_name,
                            &row.event_data,
                            &["SubjectUserSid", "TargetSid", "UserSid", "Sid"],
                        );
                        add_context_observations_from_event_data(
                            &mut observed_devices_by_executable,
                            &exe_name,
                            &row.event_data,
                            &[
                                "WorkstationName",
                                "Workstation",
                                "Computer",
                                "ClientMachine",
                            ],
                        );
                        let ts = row.timestamp;
                        let entry = evtx_security_by_executable
                            .entry(exe_name)
                            .or_insert((0, None));
                        entry.0 = entry.0.saturating_add(1);
                        entry.1 = match (entry.1, ts) {
                            (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                            (Some(a), None) => Some(a),
                            (None, Some(b)) => Some(b),
                            (None, None) => None,
                        };
                    }
                }
                Err(e) => warnings.push(format!(
                    "Could not parse EVTX security input {}: {}",
                    path.display(),
                    e
                )),
            }
        } else {
            warnings.push(format!("EVTX security input not found: {}", path.display()));
        }
    }

    let mut evtx_sysmon_rows_total = 0usize;
    let mut evtx_sysmon_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    if let Some(path) = evtx_sysmon_input.as_ref() {
        if path.exists() {
            match parse_system_log_with_metadata(path) {
                Ok(parsed) => {
                    if !parsed.metadata.quality_flags.is_empty() {
                        warnings.push(format!(
                            "EVTX sysmon quality flags: {}",
                            parsed.metadata.quality_flags.join(",")
                        ));
                    }
                    evtx_sysmon_rows_total = parsed.entries.len();
                    for row in parsed.entries {
                        let exe = row
                            .event_data
                            .get("Image")
                            .and_then(|v| executable_name_from_hint(v))
                            .or_else(|| {
                                row.event_data
                                    .get("ProcessName")
                                    .and_then(|v| executable_name_from_hint(v))
                            })
                            .or_else(|| {
                                row.event_data
                                    .get("NewProcessName")
                                    .and_then(|v| executable_name_from_hint(v))
                            })
                            .or_else(|| {
                                row.event_data
                                    .get("ParentImage")
                                    .and_then(|v| executable_name_from_hint(v))
                            });
                        let Some(exe_name) = exe else {
                            continue;
                        };
                        add_context_observation(
                            &mut observed_users_by_executable,
                            &exe_name,
                            row.user.as_deref(),
                        );
                        add_context_observation(
                            &mut observed_devices_by_executable,
                            &exe_name,
                            row.computer.as_deref(),
                        );
                        add_context_observations_from_event_data(
                            &mut observed_users_by_executable,
                            &exe_name,
                            &row.event_data,
                            &["User", "UserName", "TargetUserName"],
                        );
                        add_context_observations_from_event_data(
                            &mut observed_devices_by_executable,
                            &exe_name,
                            &row.event_data,
                            &["Computer", "Workstation", "WorkstationName"],
                        );
                        add_context_observations_from_event_data(
                            &mut observed_sids_by_executable,
                            &exe_name,
                            &row.event_data,
                            &["UserSid", "Sid"],
                        );
                        let ts = row.timestamp;
                        let entry = evtx_sysmon_by_executable
                            .entry(exe_name)
                            .or_insert((0, None));
                        entry.0 = entry.0.saturating_add(1);
                        entry.1 = match (entry.1, ts) {
                            (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                            (Some(a), None) => Some(a),
                            (None, Some(b)) => Some(b),
                            (None, None) => None,
                        };
                    }
                }
                Err(e) => warnings.push(format!(
                    "Could not parse EVTX sysmon input {}: {}",
                    path.display(),
                    e
                )),
            }
        } else {
            warnings.push(format!("EVTX sysmon input not found: {}", path.display()));
        }
    }

    let mut powershell_rows_total = 0usize;
    let mut powershell_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();

    if let Some(path) = powershell_history_input.as_ref() {
        if path.exists() {
            let rows = parse_powershell_history_file(path);
            powershell_rows_total = powershell_rows_total.saturating_add(rows.len());
            for row in rows {
                let Some(exe_name) = executable_name_from_command_text(&row.command) else {
                    continue;
                };
                let entry = powershell_by_executable
                    .entry(exe_name)
                    .or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
            }
        } else {
            warnings.push(format!(
                "PowerShell history input not found: {}",
                path.display()
            ));
        }
    }

    if let Some(path) = powershell_script_log_input.as_ref() {
        if path.exists() {
            let rows = parse_powershell_script_log_file(path);
            powershell_rows_total = powershell_rows_total.saturating_add(rows.len());
            for row in rows {
                let text = format!("{} {}", row.script_path, row.parameters);
                let Some(exe_name) = executable_name_from_command_text(&text) else {
                    continue;
                };
                let ts = if row.timestamp > 0 {
                    Some(row.timestamp as i64)
                } else {
                    None
                };
                let entry = powershell_by_executable
                    .entry(exe_name)
                    .or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = match (entry.1, ts) {
                    (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
            }
        } else {
            warnings.push(format!(
                "PowerShell script log input not found: {}",
                path.display()
            ));
        }
    }

    if let Some(path) = powershell_events_input.as_ref() {
        if path.exists() {
            let rows = parse_powershell_events_file(path);
            powershell_rows_total = powershell_rows_total.saturating_add(rows.len());
            for row in rows {
                let Some(exe_name) = executable_name_from_command_text(&row.script) else {
                    continue;
                };
                let ts = if row.timestamp > 0 {
                    Some(row.timestamp as i64)
                } else {
                    None
                };
                let entry = powershell_by_executable
                    .entry(exe_name)
                    .or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = match (entry.1, ts) {
                    (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
            }
        } else {
            warnings.push(format!(
                "PowerShell events input not found: {}",
                path.display()
            ));
        }
    }

    let mut registry_user_hives_rows_total = 0usize;
    let mut registry_user_hives_by_executable: std::collections::HashMap<
        String,
        (u32, Option<i64>),
    > = std::collections::HashMap::new();

    if let Some(path) = runmru_reg_input.as_ref() {
        if path.exists() {
            let rows = forensic_engine::classification::regmru::get_run_mru_from_reg(path);
            registry_user_hives_rows_total =
                registry_user_hives_rows_total.saturating_add(rows.len());
            for row in rows {
                let Some(exe_name) = executable_name_from_command_text(&row.value) else {
                    continue;
                };
                let entry = registry_user_hives_by_executable
                    .entry(exe_name)
                    .or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
            }
        } else {
            warnings.push(format!("RunMRU input not found: {}", path.display()));
        }
    }

    if let Some(path) = opensave_reg_input.as_ref() {
        if path.exists() {
            let rows = forensic_engine::classification::regmru2::get_open_save_mru_from_reg(path);
            registry_user_hives_rows_total =
                registry_user_hives_rows_total.saturating_add(rows.len());
            for row in rows {
                let Some(exe_name) = executable_name_from_hint(&row.path) else {
                    continue;
                };
                let entry = registry_user_hives_by_executable
                    .entry(exe_name)
                    .or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
            }
        } else {
            warnings.push(format!("OpenSaveMRU input not found: {}", path.display()));
        }
    }

    if let Some(path) = userassist_reg_input.as_ref() {
        if path.exists() {
            let rows =
                forensic_engine::classification::reguserassist::get_user_assist_from_reg(path);
            registry_user_hives_rows_total =
                registry_user_hives_rows_total.saturating_add(rows.len());
            for row in rows {
                let Some(exe_name) = executable_name_from_hint(&row.program_name) else {
                    continue;
                };
                let ts = row.last_run.map(|v| v as i64);
                let entry = registry_user_hives_by_executable
                    .entry(exe_name)
                    .or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = match (entry.1, ts) {
                    (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
            }
        } else {
            warnings.push(format!("UserAssist input not found: {}", path.display()));
        }
    }

    if let Some(path) = recentdocs_reg_input.as_ref() {
        if path.exists() {
            let rows = forensic_engine::classification::regmru::get_recent_docs_from_reg(path);
            registry_user_hives_rows_total =
                registry_user_hives_rows_total.saturating_add(rows.len());
            for row in rows {
                let Some(exe_name) = executable_name_from_hint(&row.name) else {
                    continue;
                };
                let ts = row.timestamp.map(|v| v as i64);
                let entry = registry_user_hives_by_executable
                    .entry(exe_name)
                    .or_insert((0, None));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = match (entry.1, ts) {
                    (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
            }
        } else {
            warnings.push(format!("RecentDocs input not found: {}", path.display()));
        }
    }

    let mut registry_persistence_rows_total = 0usize;
    let mut registry_persistence_by_executable: std::collections::HashMap<
        String,
        (u32, Option<i64>),
    > = std::collections::HashMap::new();

    let autorun_rows = if let Some(path) = autorun_reg_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::autorun::get_auto_run_keys_from_reg(path)
        } else {
            warnings.push(format!("Autorun input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let bam_rows = if let Some(path) = bam_reg_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::regbam::get_bam_state_from_reg(path)
        } else {
            warnings.push(format!("BAM/DAM input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let amcache_rows = if let Some(path) = amcache_reg_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::amcache::get_amcache_file_entries_from_reg(path)
                .unwrap_or_else(|_| Vec::new())
        } else {
            warnings.push(format!("Amcache input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let shimcache_rows = if let Some(path) = shimcache_reg_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::regbam::get_shim_cache_from_reg(path)
        } else {
            warnings.push(format!("ShimCache input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let task_rows = if let Some(path) = tasks_root_input.as_ref() {
        if path.exists() {
            let mut rows = parse_scheduled_tasks_xml(path).unwrap_or_else(|_| Vec::new());
            if rows.is_empty() {
                rows = forensic_engine::classification::scheduledtasks::parse_scheduled_tasks_text_fallback(path);
            }
            rows
        } else {
            warnings.push(format!("Tasks root input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let services_rows = if let Some(path) = services_reg_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::regservice::get_services_config_from_reg(path)
        } else {
            warnings.push(format!("Services input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let wmi_persist_rows = if let Some(path) = wmi_persist_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::wmipersist::get_wmi_persistence_from_path(path)
        } else {
            warnings.push(format!(
                "WMI persistence input not found: {}",
                path.display()
            ));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let wmi_trace_rows = if let Some(path) = wmi_traces_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::wmitrace::get_wmi_traces_from_path(path)
        } else {
            warnings.push(format!("WMI traces input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let wmi_instance_rows = if let Some(path) = wmi_instances_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::wmiinst::get_wmi_class_instances_from_path(path)
        } else {
            warnings.push(format!("WMI instances input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let mft_rows = if let Some(path) = mft_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::mftparse::parse_mft_records_from_path(path, limit)
        } else {
            warnings.push(format!("MFT input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let usn_rows = if let Some(path) = usn_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::usnjrnl::parse_usnjrnl_records_from_path(path)
        } else {
            warnings.push(format!("USN input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let logfile_rows = if let Some(path) = logfile_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::logfile::parse_ntfs_logfile_signals_from_path(
                path, limit,
            )
        } else {
            warnings.push(format!("NTFS LogFile input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let recycle_rows = if let Some(path) = recycle_input.as_ref() {
        if path.exists() {
            forensic_engine::classification::recyclebin::parse_recycle_entries_from_path(
                path, limit,
            )
        } else {
            warnings.push(format!("Recycle Bin input not found: {}", path.display()));
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let mut bam_dam_rows_total = 0usize;
    let mut bam_dam_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    for row in &bam_rows {
        let Some(exe_name) = executable_name_from_hint(&row.program_path) else {
            continue;
        };
        bam_dam_rows_total = bam_dam_rows_total.saturating_add(1);
        let ts = row.last_execution.map(|v| v as i64);
        let entry = bam_dam_by_executable.entry(exe_name).or_insert((0, None));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = match (entry.1, ts) {
            (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
    }

    let mut amcache_deep_rows_total = 0usize;
    let mut amcache_deep_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    for row in &amcache_rows {
        let Some(exe_name) = executable_name_from_hint(&row.file_path) else {
            continue;
        };
        amcache_deep_rows_total = amcache_deep_rows_total.saturating_add(1);
        let ts = if row.last_modified > 0 {
            Some(row.last_modified as i64)
        } else if row.created > 0 {
            Some(row.created as i64)
        } else {
            None
        };
        let entry = amcache_deep_by_executable
            .entry(exe_name)
            .or_insert((0, None));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = match (entry.1, ts) {
            (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
    }

    let mut shimcache_rows_total = 0usize;
    let mut shimcache_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    for row in &shimcache_rows {
        let Some(exe_name) = executable_name_from_hint(&row.path) else {
            continue;
        };
        shimcache_rows_total = shimcache_rows_total.saturating_add(1);
        let ts = row.last_modified.map(|v| v as i64);
        let entry = shimcache_by_executable.entry(exe_name).or_insert((0, None));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = match (entry.1, ts) {
            (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
    }

    let mut services_drivers_rows_total = 0usize;
    let mut services_drivers_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    for row in &services_rows {
        let Some(exe_name) = executable_name_from_hint(&row.path) else {
            continue;
        };
        services_drivers_rows_total = services_drivers_rows_total.saturating_add(1);
        let entry = services_drivers_by_executable
            .entry(exe_name)
            .or_insert((0, None));
        entry.0 = entry.0.saturating_add(1);
    }

    let mut scheduled_tasks_rows_total = 0usize;
    let mut scheduled_tasks_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    for row in &task_rows {
        let ts = row.last_run_time.or(row.next_run_time);
        for action in &row.actions {
            let exe_name = action
                .path
                .as_deref()
                .and_then(executable_name_from_hint)
                .or_else(|| {
                    action
                        .arguments
                        .as_deref()
                        .and_then(executable_name_from_command_text)
                });
            let Some(exe_name) = exe_name else {
                continue;
            };
            scheduled_tasks_rows_total = scheduled_tasks_rows_total.saturating_add(1);
            let entry = scheduled_tasks_by_executable
                .entry(exe_name)
                .or_insert((0, None));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = match (entry.1, ts) {
                (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
        }
    }

    let mut wmi_persistence_rows_total = 0usize;
    let mut wmi_persistence_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    for row in &wmi_persist_rows {
        let exe_name = executable_name_from_command_text(&row.consumer)
            .or_else(|| executable_name_from_command_text(&row.filter))
            .or_else(|| executable_name_from_hint(&row.consumer))
            .or_else(|| executable_name_from_hint(&row.filter));
        let Some(exe_name) = exe_name else {
            continue;
        };
        wmi_persistence_rows_total = wmi_persistence_rows_total.saturating_add(1);
        let entry = wmi_persistence_by_executable
            .entry(exe_name)
            .or_insert((0, None));
        entry.0 = entry.0.saturating_add(1);
    }
    for row in &wmi_trace_rows {
        let Some(exe_name) = executable_name_from_hint(&row.namespace) else {
            continue;
        };
        wmi_persistence_rows_total = wmi_persistence_rows_total.saturating_add(1);
        let ts = if row.timestamp > 0 {
            Some(row.timestamp as i64)
        } else {
            None
        };
        let entry = wmi_persistence_by_executable
            .entry(exe_name)
            .or_insert((0, None));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = match (entry.1, ts) {
            (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
    }
    for row in &wmi_instance_rows {
        let Some(exe_name) = executable_name_from_hint(&row.class) else {
            continue;
        };
        wmi_persistence_rows_total = wmi_persistence_rows_total.saturating_add(1);
        let entry = wmi_persistence_by_executable
            .entry(exe_name)
            .or_insert((0, None));
        entry.0 = entry.0.saturating_add(1);
    }

    let mut ntfs_mft_rows_total = 0usize;
    let mut ntfs_mft_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    let mft_paths = forensic_engine::classification::mftparse::reconstruct_mft_paths(&mft_rows)
        .into_iter()
        .map(|v| (v.record_number, v.path))
        .collect::<std::collections::BTreeMap<u64, String>>();
    for row in &mft_rows {
        let path_hint = mft_paths
            .get(&row.record_number)
            .filter(|v| !v.trim().is_empty())
            .cloned()
            .or_else(|| row.file_name.clone());
        let Some(path_hint) = path_hint else {
            continue;
        };
        let Some(exe_name) = executable_name_from_hint(&path_hint) else {
            continue;
        };
        ntfs_mft_rows_total = ntfs_mft_rows_total.saturating_add(1);
        let ts = row
            .modified_time
            .or(row.created_time)
            .or(row.mft_modified_time)
            .or(row.accessed_time);
        let entry = ntfs_mft_by_executable.entry(exe_name).or_insert((0, None));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = match (entry.1, ts) {
            (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
    }

    let mut usn_journal_rows_total = 0usize;
    let mut usn_journal_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    for row in &usn_rows {
        let path_hint = row
            .file_path
            .as_deref()
            .or(row.file_name.as_deref())
            .unwrap_or_default();
        let Some(exe_name) = executable_name_from_hint(path_hint) else {
            continue;
        };
        usn_journal_rows_total = usn_journal_rows_total.saturating_add(1);
        let entry = usn_journal_by_executable
            .entry(exe_name)
            .or_insert((0, None));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = match (entry.1, row.timestamp_unix) {
            (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
    }

    let mut ntfs_logfile_rows_total = 0usize;
    let mut ntfs_logfile_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    for row in &logfile_rows {
        let exe_name = row
            .process_path
            .as_deref()
            .and_then(executable_name_from_hint)
            .or_else(|| executable_name_from_command_text(&row.context))
            .or_else(|| executable_name_from_hint(&row.context));
        let Some(exe_name) = exe_name else {
            continue;
        };
        add_context_observation(
            &mut observed_users_by_executable,
            &exe_name,
            row.user.as_deref(),
        );
        add_context_observation(
            &mut observed_devices_by_executable,
            &exe_name,
            row.device.as_deref(),
        );
        add_context_observation(
            &mut observed_sids_by_executable,
            &exe_name,
            row.sid.as_deref(),
        );
        ntfs_logfile_rows_total = ntfs_logfile_rows_total.saturating_add(1);
        let ts = row.timestamp_unix.or_else(|| {
            row.timestamp_utc
                .as_deref()
                .and_then(parse_utc_to_unix_seconds)
        });
        let entry = ntfs_logfile_by_executable
            .entry(exe_name)
            .or_insert((0, None));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = match (entry.1, ts) {
            (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
    }

    let mut recycle_bin_rows_total = 0usize;
    let mut recycle_bin_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    for row in &recycle_rows {
        let path_hint = row
            .original_path
            .as_deref()
            .unwrap_or(row.file_name.as_str());
        let Some(exe_name) = executable_name_from_hint(path_hint)
            .or_else(|| executable_name_from_hint(&row.file_name))
        else {
            continue;
        };
        add_context_observation(
            &mut observed_sids_by_executable,
            &exe_name,
            row.owner_sid.as_deref(),
        );
        recycle_bin_rows_total = recycle_bin_rows_total.saturating_add(1);
        let entry = recycle_bin_by_executable
            .entry(exe_name)
            .or_insert((0, None));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = match (entry.1, row.deleted_time) {
            (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
    }

    let mut defender_rows_total = 0usize;
    let mut defender_rows_with_executable = 0usize;
    let mut defender_rows_without_executable = 0usize;
    let mut defender_rows_by_dataset: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut defender_correlated_by_dataset: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut defender_by_executable: std::collections::HashMap<String, (u32, Option<i64>)> =
        std::collections::HashMap::new();
    if let Some(path) = defender_input.as_ref() {
        if path.exists() {
            match load_defender_artifacts_payload(path) {
                Ok((payload, envelope_note)) => {
                    if let Some(note) = envelope_note {
                        warnings.push(note);
                    }

                    if payload.get("status").is_some() {
                        defender_rows_total = defender_rows_total.saturating_add(1);
                        *defender_rows_by_dataset
                            .entry("status".to_string())
                            .or_insert(0) += 1;
                        defender_rows_without_executable =
                            defender_rows_without_executable.saturating_add(1);
                    }

                    if let Some(rows) = payload.get("quarantine_items").and_then(|v| v.as_array()) {
                        defender_rows_total = defender_rows_total.saturating_add(rows.len());
                        *defender_rows_by_dataset
                            .entry("quarantine_items".to_string())
                            .or_insert(0) += rows.len();
                        for row in rows {
                            let exe_name = executable_name_from_json_fields(
                                row,
                                &["file_path", "resource", "path", "file_name", "threat_name"],
                            );
                            let Some(exe_name) = exe_name else {
                                defender_rows_without_executable =
                                    defender_rows_without_executable.saturating_add(1);
                                continue;
                            };
                            let ts = json_field_unix_seconds(
                                row,
                                "quarantine_time_unix",
                                "quarantine_time_utc",
                            );
                            increment_executable_counter(&mut defender_by_executable, exe_name, ts);
                            defender_rows_with_executable =
                                defender_rows_with_executable.saturating_add(1);
                            *defender_correlated_by_dataset
                                .entry("quarantine_items".to_string())
                                .or_insert(0) += 1;
                        }
                    }

                    if let Some(rows) = payload
                        .get("endpoint")
                        .and_then(|v| v.get("alerts"))
                        .and_then(|v| v.as_array())
                    {
                        defender_rows_total = defender_rows_total.saturating_add(rows.len());
                        *defender_rows_by_dataset
                            .entry("endpoint_alerts".to_string())
                            .or_insert(0) += rows.len();
                        for row in rows {
                            let exe_name = executable_name_from_json_fields(
                                row,
                                &[
                                    "title",
                                    "description",
                                    "command_line",
                                    "evidence",
                                    "process",
                                    "file_path",
                                    "machine_name",
                                ],
                            );
                            let Some(exe_name) = exe_name else {
                                defender_rows_without_executable =
                                    defender_rows_without_executable.saturating_add(1);
                                continue;
                            };
                            let ts = json_field_unix_seconds(row, "detected_unix", "detected_utc");
                            increment_executable_counter(&mut defender_by_executable, exe_name, ts);
                            defender_rows_with_executable =
                                defender_rows_with_executable.saturating_add(1);
                            *defender_correlated_by_dataset
                                .entry("endpoint_alerts".to_string())
                                .or_insert(0) += 1;
                        }
                    }

                    if let Some(rows) = payload
                        .get("endpoint")
                        .and_then(|v| v.get("indicators"))
                        .and_then(|v| v.as_array())
                    {
                        defender_rows_total = defender_rows_total.saturating_add(rows.len());
                        *defender_rows_by_dataset
                            .entry("endpoint_indicators".to_string())
                            .or_insert(0) += rows.len();
                        for row in rows {
                            let exe_name = executable_name_from_json_fields(
                                row,
                                &["value", "title", "description", "path", "file_path"],
                            );
                            let Some(exe_name) = exe_name else {
                                defender_rows_without_executable =
                                    defender_rows_without_executable.saturating_add(1);
                                continue;
                            };
                            let ts = json_field_unix_seconds(row, "created_unix", "created_utc");
                            increment_executable_counter(&mut defender_by_executable, exe_name, ts);
                            defender_rows_with_executable =
                                defender_rows_with_executable.saturating_add(1);
                            *defender_correlated_by_dataset
                                .entry("endpoint_indicators".to_string())
                                .or_insert(0) += 1;
                        }
                    }

                    if let Some(rows) = payload
                        .get("endpoint")
                        .and_then(|v| v.get("file_profiles"))
                        .and_then(|v| v.as_array())
                    {
                        defender_rows_total = defender_rows_total.saturating_add(rows.len());
                        *defender_rows_by_dataset
                            .entry("endpoint_file_profiles".to_string())
                            .or_insert(0) += rows.len();
                        for row in rows {
                            let exe_name = executable_name_from_json_fields(
                                row,
                                &["file_name", "file_path", "path", "description"],
                            );
                            let Some(exe_name) = exe_name else {
                                defender_rows_without_executable =
                                    defender_rows_without_executable.saturating_add(1);
                                continue;
                            };
                            let ts =
                                json_field_unix_seconds(row, "first_seen_unix", "first_seen_utc");
                            increment_executable_counter(&mut defender_by_executable, exe_name, ts);
                            defender_rows_with_executable =
                                defender_rows_with_executable.saturating_add(1);
                            *defender_correlated_by_dataset
                                .entry("endpoint_file_profiles".to_string())
                                .or_insert(0) += 1;
                        }
                    }

                    if let Some(rows) = payload
                        .get("endpoint")
                        .and_then(|v| v.get("machine_actions"))
                        .and_then(|v| v.as_array())
                    {
                        defender_rows_total = defender_rows_total.saturating_add(rows.len());
                        *defender_rows_by_dataset
                            .entry("endpoint_machine_actions".to_string())
                            .or_insert(0) += rows.len();
                        for row in rows {
                            let exe_name = executable_name_from_json_fields(
                                row,
                                &["comment", "action", "description"],
                            );
                            let Some(exe_name) = exe_name else {
                                defender_rows_without_executable =
                                    defender_rows_without_executable.saturating_add(1);
                                continue;
                            };
                            let ts =
                                json_field_unix_seconds(row, "requested_unix", "requested_utc")
                                    .or_else(|| {
                                        json_field_unix_seconds(
                                            row,
                                            "completed_unix",
                                            "completed_utc",
                                        )
                                    });
                            increment_executable_counter(&mut defender_by_executable, exe_name, ts);
                            defender_rows_with_executable =
                                defender_rows_with_executable.saturating_add(1);
                            *defender_correlated_by_dataset
                                .entry("endpoint_machine_actions".to_string())
                                .or_insert(0) += 1;
                        }
                    }

                    if let Some(rows) = payload.get("scan_history").and_then(|v| v.as_array()) {
                        defender_rows_total = defender_rows_total.saturating_add(rows.len());
                        *defender_rows_by_dataset
                            .entry("scan_history".to_string())
                            .or_insert(0) += rows.len();
                        for row in rows {
                            let exe_name = executable_name_from_json_fields(
                                row,
                                &["scan_target", "scan_path", "path", "result_summary"],
                            );
                            let Some(exe_name) = exe_name else {
                                defender_rows_without_executable =
                                    defender_rows_without_executable.saturating_add(1);
                                continue;
                            };
                            let ts = json_field_unix_seconds(row, "end_time_unix", "end_time_utc")
                                .or_else(|| {
                                    json_field_unix_seconds(
                                        row,
                                        "start_time_unix",
                                        "start_time_utc",
                                    )
                                });
                            increment_executable_counter(&mut defender_by_executable, exe_name, ts);
                            defender_rows_with_executable =
                                defender_rows_with_executable.saturating_add(1);
                            *defender_correlated_by_dataset
                                .entry("scan_history".to_string())
                                .or_insert(0) += 1;
                        }
                    }
                }
                Err(e) => warnings.push(format!(
                    "Could not parse Defender artifacts input {}: {}",
                    path.display(),
                    e
                )),
            }
        } else {
            warnings.push(format!("Defender input not found: {}", path.display()));
        }
    }
    if defender_rows_total > 0 && defender_by_executable.is_empty() {
        warnings.push(
            "Defender artifacts input had rows, but none could be correlated to executable names"
                .to_string(),
        );
    } else if defender_rows_without_executable > 0 {
        warnings.push(format!(
            "Defender artifacts rows without executable correlation: {}",
            defender_rows_without_executable
        ));
    }

    if !autorun_rows.is_empty()
        || !bam_rows.is_empty()
        || !amcache_rows.is_empty()
        || !task_rows.is_empty()
    {
        let correlations = build_persistence_correlations_with_amcache(
            &autorun_rows,
            &task_rows,
            &bam_rows,
            &amcache_rows,
        );
        registry_persistence_rows_total = correlations.len();
        for row in correlations {
            let Some(exe_name) = executable_name_from_hint(&row.executable_path) else {
                continue;
            };
            let ts = row.latest_execution_unix.map(|v| v as i64);
            let entry = registry_persistence_by_executable
                .entry(exe_name)
                .or_insert((0, None));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = match (entry.1, ts) {
                (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
        }
    }

    let all_rows = build_execution_correlations(&prefetch, &jumplist, &shortcuts);
    let total_available = all_rows.len();
    let correlations = all_rows
        .into_iter()
        .take(limit)
        .map(|row| {
            let (srum_count, latest_srum_unix) = srum_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (evtx_security_count, latest_evtx_security_unix) = evtx_security_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (evtx_sysmon_count, latest_evtx_sysmon_unix) = evtx_sysmon_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (powershell_count, latest_powershell_unix) = powershell_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (registry_user_hives_count, latest_registry_user_hives_unix) =
                registry_user_hives_by_executable
                    .get(&row.executable_name)
                    .copied()
                    .unwrap_or((0, None));
            let (registry_persistence_count, latest_registry_persistence_unix) =
                registry_persistence_by_executable
                    .get(&row.executable_name)
                    .copied()
                    .unwrap_or((0, None));
            let (shimcache_count, latest_shimcache_unix) = shimcache_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (amcache_deep_count, latest_amcache_deep_unix) = amcache_deep_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (bam_dam_activity_count, latest_bam_dam_activity_unix) = bam_dam_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (services_drivers_count, latest_services_drivers_unix) =
                services_drivers_by_executable
                    .get(&row.executable_name)
                    .copied()
                    .unwrap_or((0, None));
            let (scheduled_tasks_count, latest_scheduled_tasks_unix) =
                scheduled_tasks_by_executable
                    .get(&row.executable_name)
                    .copied()
                    .unwrap_or((0, None));
            let (wmi_persistence_count, latest_wmi_persistence_unix) =
                wmi_persistence_by_executable
                    .get(&row.executable_name)
                    .copied()
                    .unwrap_or((0, None));
            let (ntfs_mft_count, latest_ntfs_mft_unix) = ntfs_mft_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (usn_journal_count, latest_usn_journal_unix) = usn_journal_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (ntfs_logfile_count, latest_ntfs_logfile_unix) = ntfs_logfile_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (recycle_bin_count, latest_recycle_bin_unix) = recycle_bin_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (browser_forensics_count, latest_browser_forensics_unix) = browser_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (rdp_remote_access_count, latest_rdp_remote_access_unix) = rdp_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (usb_device_history_count, latest_usb_device_history_unix) = usb_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let (restore_shadow_copies_count, latest_restore_shadow_copies_unix) =
                restore_shadow_by_executable
                    .get(&row.executable_name)
                    .copied()
                    .unwrap_or((0, None));
            let (user_activity_mru_count, latest_user_activity_mru_unix) =
                user_activity_by_executable
                    .get(&row.executable_name)
                    .copied()
                    .unwrap_or((0, None));
            let (timeline_correlation_qa_count, latest_timeline_correlation_qa_unix) =
                timeline_correlation_by_executable
                    .get(&row.executable_name)
                    .copied()
                    .unwrap_or((0, None));
            let (defender_artifacts_count, latest_defender_artifacts_unix) = defender_by_executable
                .get(&row.executable_name)
                .copied()
                .unwrap_or((0, None));
            let mut merged_sources = row.sources.clone();
            if srum_count > 0 && !merged_sources.iter().any(|s| s == "srum") {
                merged_sources.push("srum".to_string());
            }
            if evtx_security_count > 0 && !merged_sources.iter().any(|s| s == "evtx-security") {
                merged_sources.push("evtx-security".to_string());
            }
            if evtx_sysmon_count > 0 && !merged_sources.iter().any(|s| s == "evtx-sysmon") {
                merged_sources.push("evtx-sysmon".to_string());
            }
            if powershell_count > 0 && !merged_sources.iter().any(|s| s == "powershell") {
                merged_sources.push("powershell".to_string());
            }
            if registry_user_hives_count > 0
                && !merged_sources.iter().any(|s| s == "registry-user-hives")
            {
                merged_sources.push("registry-user-hives".to_string());
            }
            if registry_persistence_count > 0
                && !merged_sources.iter().any(|s| s == "registry-persistence")
            {
                merged_sources.push("registry-persistence".to_string());
            }
            if shimcache_count > 0 && !merged_sources.iter().any(|s| s == "shimcache") {
                merged_sources.push("shimcache".to_string());
            }
            if amcache_deep_count > 0 && !merged_sources.iter().any(|s| s == "amcache") {
                merged_sources.push("amcache".to_string());
            }
            if bam_dam_activity_count > 0 && !merged_sources.iter().any(|s| s == "bam-dam") {
                merged_sources.push("bam-dam".to_string());
            }
            if services_drivers_count > 0 && !merged_sources.iter().any(|s| s == "services-drivers")
            {
                merged_sources.push("services-drivers".to_string());
            }
            if scheduled_tasks_count > 0 && !merged_sources.iter().any(|s| s == "scheduled-tasks") {
                merged_sources.push("scheduled-tasks".to_string());
            }
            if wmi_persistence_count > 0 && !merged_sources.iter().any(|s| s == "wmi-persistence") {
                merged_sources.push("wmi-persistence".to_string());
            }
            if ntfs_mft_count > 0 && !merged_sources.iter().any(|s| s == "ntfs-mft") {
                merged_sources.push("ntfs-mft".to_string());
            }
            if usn_journal_count > 0 && !merged_sources.iter().any(|s| s == "usn-journal") {
                merged_sources.push("usn-journal".to_string());
            }
            if ntfs_logfile_count > 0 && !merged_sources.iter().any(|s| s == "ntfs-logfile") {
                merged_sources.push("ntfs-logfile".to_string());
            }
            if recycle_bin_count > 0 && !merged_sources.iter().any(|s| s == "recycle-bin") {
                merged_sources.push("recycle-bin".to_string());
            }
            if browser_forensics_count > 0
                && !merged_sources.iter().any(|s| s == "browser-forensics")
            {
                merged_sources.push("browser-forensics".to_string());
            }
            if rdp_remote_access_count > 0
                && !merged_sources.iter().any(|s| s == "rdp-remote-access")
            {
                merged_sources.push("rdp-remote-access".to_string());
            }
            if usb_device_history_count > 0
                && !merged_sources.iter().any(|s| s == "usb-device-history")
            {
                merged_sources.push("usb-device-history".to_string());
            }
            if restore_shadow_copies_count > 0
                && !merged_sources.iter().any(|s| s == "restore-shadow-copies")
            {
                merged_sources.push("restore-shadow-copies".to_string());
            }
            if user_activity_mru_count > 0
                && !merged_sources.iter().any(|s| s == "user-activity-mru")
            {
                merged_sources.push("user-activity-mru".to_string());
            }
            if timeline_correlation_qa_count > 0
                && !merged_sources
                    .iter()
                    .any(|s| s == "timeline-correlation-qa")
            {
                merged_sources.push("timeline-correlation-qa".to_string());
            }
            if defender_artifacts_count > 0
                && !merged_sources.iter().any(|s| s == "defender-artifacts")
            {
                merged_sources.push("defender-artifacts".to_string());
            }
            merged_sources.sort();

            let total_hits_with_context = row
                .total_hits
                .saturating_add(srum_count)
                .saturating_add(evtx_security_count)
                .saturating_add(evtx_sysmon_count)
                .saturating_add(powershell_count)
                .saturating_add(registry_user_hives_count)
                .saturating_add(registry_persistence_count)
                .saturating_add(shimcache_count)
                .saturating_add(amcache_deep_count)
                .saturating_add(bam_dam_activity_count)
                .saturating_add(services_drivers_count)
                .saturating_add(scheduled_tasks_count)
                .saturating_add(wmi_persistence_count)
                .saturating_add(ntfs_mft_count)
                .saturating_add(usn_journal_count)
                .saturating_add(ntfs_logfile_count)
                .saturating_add(recycle_bin_count)
                .saturating_add(browser_forensics_count)
                .saturating_add(rdp_remote_access_count)
                .saturating_add(usb_device_history_count)
                .saturating_add(restore_shadow_copies_count)
                .saturating_add(user_activity_mru_count)
                .saturating_add(timeline_correlation_qa_count)
                .saturating_add(defender_artifacts_count);
            let observed_users =
                collect_context_observations(&observed_users_by_executable, &row.executable_name);
            let observed_devices =
                collect_context_observations(&observed_devices_by_executable, &row.executable_name);
            let observed_sids =
                collect_context_observations(&observed_sids_by_executable, &row.executable_name);

            let mut map = serde_json::Map::new();
            map.insert(
                "executable_name".to_string(),
                serde_json::Value::String(row.executable_name),
            );
            map.insert("sources".to_string(), serde_json::json!(merged_sources));
            map.insert(
                "prefetch_count".to_string(),
                serde_json::json!(row.prefetch_count),
            );
            map.insert(
                "jumplist_count".to_string(),
                serde_json::json!(row.jumplist_count),
            );
            map.insert(
                "shortcut_count".to_string(),
                serde_json::json!(row.shortcut_count),
            );
            map.insert("srum_count".to_string(), serde_json::json!(srum_count));
            map.insert(
                "evtx_security_count".to_string(),
                serde_json::json!(evtx_security_count),
            );
            map.insert(
                "evtx_sysmon_count".to_string(),
                serde_json::json!(evtx_sysmon_count),
            );
            map.insert(
                "powershell_count".to_string(),
                serde_json::json!(powershell_count),
            );
            map.insert(
                "registry_user_hives_count".to_string(),
                serde_json::json!(registry_user_hives_count),
            );
            map.insert(
                "registry_persistence_count".to_string(),
                serde_json::json!(registry_persistence_count),
            );
            map.insert(
                "shimcache_count".to_string(),
                serde_json::json!(shimcache_count),
            );
            map.insert(
                "amcache_deep_count".to_string(),
                serde_json::json!(amcache_deep_count),
            );
            map.insert(
                "bam_dam_activity_count".to_string(),
                serde_json::json!(bam_dam_activity_count),
            );
            map.insert(
                "services_drivers_count".to_string(),
                serde_json::json!(services_drivers_count),
            );
            map.insert(
                "scheduled_tasks_count".to_string(),
                serde_json::json!(scheduled_tasks_count),
            );
            map.insert(
                "wmi_persistence_count".to_string(),
                serde_json::json!(wmi_persistence_count),
            );
            map.insert(
                "ntfs_mft_count".to_string(),
                serde_json::json!(ntfs_mft_count),
            );
            map.insert(
                "usn_journal_count".to_string(),
                serde_json::json!(usn_journal_count),
            );
            map.insert(
                "ntfs_logfile_count".to_string(),
                serde_json::json!(ntfs_logfile_count),
            );
            map.insert(
                "recycle_bin_count".to_string(),
                serde_json::json!(recycle_bin_count),
            );
            map.insert(
                "browser_forensics_count".to_string(),
                serde_json::json!(browser_forensics_count),
            );
            map.insert(
                "rdp_remote_access_count".to_string(),
                serde_json::json!(rdp_remote_access_count),
            );
            map.insert(
                "usb_device_history_count".to_string(),
                serde_json::json!(usb_device_history_count),
            );
            map.insert(
                "restore_shadow_copies_count".to_string(),
                serde_json::json!(restore_shadow_copies_count),
            );
            map.insert(
                "user_activity_mru_count".to_string(),
                serde_json::json!(user_activity_mru_count),
            );
            map.insert(
                "timeline_correlation_qa_count".to_string(),
                serde_json::json!(timeline_correlation_qa_count),
            );
            map.insert(
                "defender_artifacts_count".to_string(),
                serde_json::json!(defender_artifacts_count),
            );
            map.insert("total_hits".to_string(), serde_json::json!(row.total_hits));
            map.insert(
                "total_hits_with_srum".to_string(),
                serde_json::json!(row.total_hits.saturating_add(srum_count)),
            );
            map.insert(
                "total_hits_with_context".to_string(),
                serde_json::json!(total_hits_with_context),
            );
            map.insert(
                "first_seen_unix".to_string(),
                serde_json::json!(row.first_seen_unix),
            );
            map.insert(
                "first_seen_utc".to_string(),
                serde_json::json!(row.first_seen_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "last_seen_unix".to_string(),
                serde_json::json!(row.last_seen_unix),
            );
            map.insert(
                "last_seen_utc".to_string(),
                serde_json::json!(row.last_seen_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_prefetch_unix".to_string(),
                serde_json::json!(row.latest_prefetch_unix),
            );
            map.insert(
                "latest_prefetch_utc".to_string(),
                serde_json::json!(row.latest_prefetch_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_jumplist_unix".to_string(),
                serde_json::json!(row.latest_jumplist_unix),
            );
            map.insert(
                "latest_jumplist_utc".to_string(),
                serde_json::json!(row.latest_jumplist_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_shortcut_unix".to_string(),
                serde_json::json!(row.latest_shortcut_unix),
            );
            map.insert(
                "latest_shortcut_utc".to_string(),
                serde_json::json!(row.latest_shortcut_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_srum_unix".to_string(),
                serde_json::json!(latest_srum_unix),
            );
            map.insert(
                "latest_srum_utc".to_string(),
                serde_json::json!(latest_srum_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_evtx_security_unix".to_string(),
                serde_json::json!(latest_evtx_security_unix),
            );
            map.insert(
                "latest_evtx_security_utc".to_string(),
                serde_json::json!(latest_evtx_security_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_evtx_sysmon_unix".to_string(),
                serde_json::json!(latest_evtx_sysmon_unix),
            );
            map.insert(
                "latest_evtx_sysmon_utc".to_string(),
                serde_json::json!(latest_evtx_sysmon_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_powershell_unix".to_string(),
                serde_json::json!(latest_powershell_unix),
            );
            map.insert(
                "latest_powershell_utc".to_string(),
                serde_json::json!(latest_powershell_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_registry_user_hives_unix".to_string(),
                serde_json::json!(latest_registry_user_hives_unix),
            );
            map.insert(
                "latest_registry_user_hives_utc".to_string(),
                serde_json::json!(latest_registry_user_hives_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_registry_persistence_unix".to_string(),
                serde_json::json!(latest_registry_persistence_unix),
            );
            map.insert(
                "latest_registry_persistence_utc".to_string(),
                serde_json::json!(latest_registry_persistence_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_shimcache_unix".to_string(),
                serde_json::json!(latest_shimcache_unix),
            );
            map.insert(
                "latest_shimcache_utc".to_string(),
                serde_json::json!(latest_shimcache_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_amcache_deep_unix".to_string(),
                serde_json::json!(latest_amcache_deep_unix),
            );
            map.insert(
                "latest_amcache_deep_utc".to_string(),
                serde_json::json!(latest_amcache_deep_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_bam_dam_activity_unix".to_string(),
                serde_json::json!(latest_bam_dam_activity_unix),
            );
            map.insert(
                "latest_bam_dam_activity_utc".to_string(),
                serde_json::json!(latest_bam_dam_activity_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_services_drivers_unix".to_string(),
                serde_json::json!(latest_services_drivers_unix),
            );
            map.insert(
                "latest_services_drivers_utc".to_string(),
                serde_json::json!(latest_services_drivers_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_scheduled_tasks_unix".to_string(),
                serde_json::json!(latest_scheduled_tasks_unix),
            );
            map.insert(
                "latest_scheduled_tasks_utc".to_string(),
                serde_json::json!(latest_scheduled_tasks_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_wmi_persistence_unix".to_string(),
                serde_json::json!(latest_wmi_persistence_unix),
            );
            map.insert(
                "latest_wmi_persistence_utc".to_string(),
                serde_json::json!(latest_wmi_persistence_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_ntfs_mft_unix".to_string(),
                serde_json::json!(latest_ntfs_mft_unix),
            );
            map.insert(
                "latest_ntfs_mft_utc".to_string(),
                serde_json::json!(latest_ntfs_mft_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_usn_journal_unix".to_string(),
                serde_json::json!(latest_usn_journal_unix),
            );
            map.insert(
                "latest_usn_journal_utc".to_string(),
                serde_json::json!(latest_usn_journal_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_ntfs_logfile_unix".to_string(),
                serde_json::json!(latest_ntfs_logfile_unix),
            );
            map.insert(
                "latest_ntfs_logfile_utc".to_string(),
                serde_json::json!(latest_ntfs_logfile_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_recycle_bin_unix".to_string(),
                serde_json::json!(latest_recycle_bin_unix),
            );
            map.insert(
                "latest_recycle_bin_utc".to_string(),
                serde_json::json!(latest_recycle_bin_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_browser_forensics_unix".to_string(),
                serde_json::json!(latest_browser_forensics_unix),
            );
            map.insert(
                "latest_browser_forensics_utc".to_string(),
                serde_json::json!(latest_browser_forensics_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_rdp_remote_access_unix".to_string(),
                serde_json::json!(latest_rdp_remote_access_unix),
            );
            map.insert(
                "latest_rdp_remote_access_utc".to_string(),
                serde_json::json!(latest_rdp_remote_access_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_usb_device_history_unix".to_string(),
                serde_json::json!(latest_usb_device_history_unix),
            );
            map.insert(
                "latest_usb_device_history_utc".to_string(),
                serde_json::json!(latest_usb_device_history_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_restore_shadow_copies_unix".to_string(),
                serde_json::json!(latest_restore_shadow_copies_unix),
            );
            map.insert(
                "latest_restore_shadow_copies_utc".to_string(),
                serde_json::json!(latest_restore_shadow_copies_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_user_activity_mru_unix".to_string(),
                serde_json::json!(latest_user_activity_mru_unix),
            );
            map.insert(
                "latest_user_activity_mru_utc".to_string(),
                serde_json::json!(latest_user_activity_mru_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_timeline_correlation_qa_unix".to_string(),
                serde_json::json!(latest_timeline_correlation_qa_unix),
            );
            map.insert(
                "latest_timeline_correlation_qa_utc".to_string(),
                serde_json::json!(latest_timeline_correlation_qa_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "latest_defender_artifacts_unix".to_string(),
                serde_json::json!(latest_defender_artifacts_unix),
            );
            map.insert(
                "latest_defender_artifacts_utc".to_string(),
                serde_json::json!(latest_defender_artifacts_unix.map(unix_seconds_to_utc)),
            );
            map.insert(
                "sample_paths".to_string(),
                serde_json::json!(row.sample_paths),
            );
            map.insert(
                "observed_users".to_string(),
                serde_json::json!(observed_users),
            );
            map.insert(
                "observed_devices".to_string(),
                serde_json::json!(observed_devices),
            );
            map.insert(
                "observed_sids".to_string(),
                serde_json::json!(observed_sids),
            );

            serde_json::Value::Object(map)
        })
        .collect::<Vec<_>>();

    if correlations.is_empty() && warnings.is_empty() {
        warnings
            .push("No execution correlations found from provided execution sources".to_string());
    }

    let mut inputs = serde_json::Map::new();
    inputs.insert(
        "prefetch_dir".to_string(),
        serde_json::json!(prefetch_dir.to_string_lossy().to_string()),
    );
    inputs.insert(
        "prefetch_found".to_string(),
        serde_json::json!(prefetch_dir.exists()),
    );
    inputs.insert(
        "jumplist_path".to_string(),
        serde_json::json!(jumplist_path.to_string_lossy().to_string()),
    );
    inputs.insert(
        "jumplist_found".to_string(),
        serde_json::json!(jumplist_path.exists()),
    );
    inputs.insert(
        "shortcuts_base".to_string(),
        serde_json::json!(shortcuts_base.to_string_lossy().to_string()),
    );
    inputs.insert(
        "shortcuts_found".to_string(),
        serde_json::json!(shortcuts_base.exists()),
    );
    inputs.insert(
        "lnk_input".to_string(),
        serde_json::json!(lnk_input.as_ref().map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "lnk_found".to_string(),
        serde_json::json!(lnk_input.as_ref().map(|p| p.exists()).unwrap_or(false)),
    );
    inputs.insert(
        "browser_input".to_string(),
        serde_json::json!(browser_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "browser_found".to_string(),
        serde_json::json!(browser_input.as_ref().map(|p| p.exists()).unwrap_or(false)),
    );
    inputs.insert(
        "rdp_input".to_string(),
        serde_json::json!(rdp_input.as_ref().map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "rdp_found".to_string(),
        serde_json::json!(rdp_input.as_ref().map(|p| p.exists()).unwrap_or(false)),
    );
    inputs.insert(
        "usb_input".to_string(),
        serde_json::json!(usb_input.as_ref().map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "usb_found".to_string(),
        serde_json::json!(usb_input.as_ref().map(|p| p.exists()).unwrap_or(false)),
    );
    inputs.insert(
        "restore_shadow_input".to_string(),
        serde_json::json!(restore_shadow_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "restore_shadow_found".to_string(),
        serde_json::json!(restore_shadow_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "user_activity_input".to_string(),
        serde_json::json!(user_activity_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "user_activity_found".to_string(),
        serde_json::json!(user_activity_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "timeline_correlation_input".to_string(),
        serde_json::json!(timeline_correlation_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "timeline_correlation_found".to_string(),
        serde_json::json!(timeline_correlation_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "srum_input".to_string(),
        serde_json::json!(srum_input.as_ref().map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "srum_found".to_string(),
        serde_json::json!(srum_input.as_ref().map(|p| p.exists()).unwrap_or(false)),
    );
    inputs.insert(
        "evtx_security_input".to_string(),
        serde_json::json!(evtx_security_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "evtx_security_found".to_string(),
        serde_json::json!(evtx_security_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "evtx_sysmon_input".to_string(),
        serde_json::json!(evtx_sysmon_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "evtx_sysmon_found".to_string(),
        serde_json::json!(evtx_sysmon_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "powershell_history".to_string(),
        serde_json::json!(powershell_history_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "powershell_history_found".to_string(),
        serde_json::json!(powershell_history_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "powershell_script_log".to_string(),
        serde_json::json!(powershell_script_log_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "powershell_script_log_found".to_string(),
        serde_json::json!(powershell_script_log_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "powershell_events".to_string(),
        serde_json::json!(powershell_events_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "powershell_events_found".to_string(),
        serde_json::json!(powershell_events_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "runmru_reg".to_string(),
        serde_json::json!(runmru_reg_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "runmru_found".to_string(),
        serde_json::json!(runmru_reg_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "opensave_reg".to_string(),
        serde_json::json!(opensave_reg_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "opensave_found".to_string(),
        serde_json::json!(opensave_reg_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "userassist_reg".to_string(),
        serde_json::json!(userassist_reg_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "userassist_found".to_string(),
        serde_json::json!(userassist_reg_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "recentdocs_reg".to_string(),
        serde_json::json!(recentdocs_reg_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "recentdocs_found".to_string(),
        serde_json::json!(recentdocs_reg_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "autorun_reg".to_string(),
        serde_json::json!(autorun_reg_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "autorun_found".to_string(),
        serde_json::json!(autorun_reg_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "bam_reg".to_string(),
        serde_json::json!(bam_reg_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "bam_found".to_string(),
        serde_json::json!(bam_reg_input.as_ref().map(|p| p.exists()).unwrap_or(false)),
    );
    inputs.insert(
        "amcache_reg".to_string(),
        serde_json::json!(amcache_reg_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "amcache_found".to_string(),
        serde_json::json!(amcache_reg_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "shimcache_reg".to_string(),
        serde_json::json!(shimcache_reg_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "shimcache_found".to_string(),
        serde_json::json!(shimcache_reg_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "services_reg".to_string(),
        serde_json::json!(services_reg_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "services_found".to_string(),
        serde_json::json!(services_reg_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "tasks_root".to_string(),
        serde_json::json!(tasks_root_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "tasks_root_found".to_string(),
        serde_json::json!(tasks_root_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "wmi_persist_input".to_string(),
        serde_json::json!(wmi_persist_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "wmi_persist_found".to_string(),
        serde_json::json!(wmi_persist_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "wmi_traces_input".to_string(),
        serde_json::json!(wmi_traces_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "wmi_traces_found".to_string(),
        serde_json::json!(wmi_traces_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "wmi_instances_input".to_string(),
        serde_json::json!(wmi_instances_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "wmi_instances_found".to_string(),
        serde_json::json!(wmi_instances_input
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)),
    );
    inputs.insert(
        "mft_input".to_string(),
        serde_json::json!(mft_input.as_ref().map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "mft_found".to_string(),
        serde_json::json!(mft_input.as_ref().map(|p| p.exists()).unwrap_or(false)),
    );
    inputs.insert(
        "usn_input".to_string(),
        serde_json::json!(usn_input.as_ref().map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "usn_found".to_string(),
        serde_json::json!(usn_input.as_ref().map(|p| p.exists()).unwrap_or(false)),
    );
    inputs.insert(
        "logfile_input".to_string(),
        serde_json::json!(logfile_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "logfile_found".to_string(),
        serde_json::json!(logfile_input.as_ref().map(|p| p.exists()).unwrap_or(false)),
    );
    inputs.insert(
        "recycle_input".to_string(),
        serde_json::json!(recycle_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "recycle_found".to_string(),
        serde_json::json!(recycle_input.as_ref().map(|p| p.exists()).unwrap_or(false)),
    );
    inputs.insert(
        "defender_input".to_string(),
        serde_json::json!(defender_input
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())),
    );
    inputs.insert(
        "defender_found".to_string(),
        serde_json::json!(defender_input.as_ref().map(|p| p.exists()).unwrap_or(false)),
    );

    let mut source_rows = serde_json::Map::new();
    source_rows.insert("prefetch".to_string(), serde_json::json!(prefetch.len()));
    source_rows.insert("jumplist".to_string(), serde_json::json!(jumplist.len()));
    source_rows.insert("shortcut".to_string(), serde_json::json!(shortcuts.len()));
    source_rows.insert(
        "browser_forensics".to_string(),
        serde_json::json!(browser_rows_total),
    );
    source_rows.insert(
        "rdp_remote_access".to_string(),
        serde_json::json!(rdp_rows_total),
    );
    source_rows.insert(
        "usb_device_history".to_string(),
        serde_json::json!(usb_rows_total),
    );
    source_rows.insert(
        "restore_shadow_copies".to_string(),
        serde_json::json!(restore_shadow_rows_total),
    );
    source_rows.insert(
        "user_activity_mru".to_string(),
        serde_json::json!(user_activity_rows_total),
    );
    source_rows.insert(
        "timeline_correlation_qa".to_string(),
        serde_json::json!(timeline_correlation_rows_total),
    );
    source_rows.insert("srum".to_string(), serde_json::json!(srum_rows_total));
    source_rows.insert(
        "evtx_security".to_string(),
        serde_json::json!(evtx_security_rows_total),
    );
    source_rows.insert(
        "evtx_sysmon".to_string(),
        serde_json::json!(evtx_sysmon_rows_total),
    );
    source_rows.insert(
        "powershell".to_string(),
        serde_json::json!(powershell_rows_total),
    );
    source_rows.insert(
        "registry_user_hives".to_string(),
        serde_json::json!(registry_user_hives_rows_total),
    );
    source_rows.insert(
        "registry_persistence".to_string(),
        serde_json::json!(registry_persistence_rows_total),
    );
    source_rows.insert(
        "shimcache".to_string(),
        serde_json::json!(shimcache_rows_total),
    );
    source_rows.insert(
        "amcache_deep".to_string(),
        serde_json::json!(amcache_deep_rows_total),
    );
    source_rows.insert(
        "bam_dam_activity".to_string(),
        serde_json::json!(bam_dam_rows_total),
    );
    source_rows.insert(
        "services_drivers".to_string(),
        serde_json::json!(services_drivers_rows_total),
    );
    source_rows.insert(
        "scheduled_tasks".to_string(),
        serde_json::json!(scheduled_tasks_rows_total),
    );
    source_rows.insert(
        "wmi_persistence".to_string(),
        serde_json::json!(wmi_persistence_rows_total),
    );
    source_rows.insert(
        "ntfs_mft".to_string(),
        serde_json::json!(ntfs_mft_rows_total),
    );
    source_rows.insert(
        "usn_journal".to_string(),
        serde_json::json!(usn_journal_rows_total),
    );
    source_rows.insert(
        "ntfs_logfile".to_string(),
        serde_json::json!(ntfs_logfile_rows_total),
    );
    source_rows.insert(
        "recycle_bin".to_string(),
        serde_json::json!(recycle_bin_rows_total),
    );
    source_rows.insert(
        "defender_artifacts".to_string(),
        serde_json::json!(defender_rows_total),
    );

    let mut defender_rows_by_dataset_json = serde_json::Map::new();
    for (dataset, count) in &defender_rows_by_dataset {
        defender_rows_by_dataset_json.insert(dataset.clone(), serde_json::json!(count));
    }
    let mut defender_correlated_by_dataset_json = serde_json::Map::new();
    for (dataset, count) in &defender_correlated_by_dataset {
        defender_correlated_by_dataset_json.insert(dataset.clone(), serde_json::json!(count));
    }

    let defender_quality = serde_json::json!({
        "rows_total": defender_rows_total,
        "rows_with_executable": defender_rows_with_executable,
        "rows_without_executable": defender_rows_without_executable,
        "rows_by_dataset": defender_rows_by_dataset_json,
        "correlated_by_dataset": defender_correlated_by_dataset_json
    });

    let mut data_map = serde_json::Map::new();
    data_map.insert("limit".to_string(), serde_json::json!(limit));
    data_map.insert(
        "total_available".to_string(),
        serde_json::json!(total_available),
    );
    data_map.insert(
        "total_returned".to_string(),
        serde_json::json!(correlations.len()),
    );
    data_map.insert("inputs".to_string(), serde_json::Value::Object(inputs));
    data_map.insert(
        "source_rows".to_string(),
        serde_json::Value::Object(source_rows),
    );
    data_map.insert("defender_quality".to_string(), defender_quality);
    data_map.insert("correlations".to_string(), serde_json::json!(correlations));

    let data = serde_json::Value::Object(data_map);

    let warning = if warnings.is_empty() {
        None
    } else {
        Some(warnings.join("; "))
    };

    if json_output && !quiet {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else if !quiet {
        println!("=== Execution Correlations ===");
        println!("Prefetch rows: {}", prefetch.len());
        println!("Jump List rows: {}", jumplist.len());
        println!("Shortcut rows: {}", shortcuts.len());
        println!("Browser rows: {}", browser_rows_total);
        println!("RDP rows: {}", rdp_rows_total);
        println!("USB rows: {}", usb_rows_total);
        println!("Restore/shadow rows: {}", restore_shadow_rows_total);
        println!("User-activity/MRU rows: {}", user_activity_rows_total);
        println!("PowerShell rows: {}", powershell_rows_total);
        println!(
            "Registry user-hive rows: {}",
            registry_user_hives_rows_total
        );
        println!(
            "Registry persistence rows: {}",
            registry_persistence_rows_total
        );
        println!("ShimCache rows: {}", shimcache_rows_total);
        println!("Amcache deep rows: {}", amcache_deep_rows_total);
        println!("BAM/DAM activity rows: {}", bam_dam_rows_total);
        println!("Services/drivers rows: {}", services_drivers_rows_total);
        println!("Scheduled-task rows: {}", scheduled_tasks_rows_total);
        println!(
            "WMI persistence/activity rows: {}",
            wmi_persistence_rows_total
        );
        println!("NTFS MFT rows: {}", ntfs_mft_rows_total);
        println!("USN journal rows: {}", usn_journal_rows_total);
        println!("NTFS LogFile rows: {}", ntfs_logfile_rows_total);
        println!("Recycle Bin rows: {}", recycle_bin_rows_total);
        println!("Defender artifact rows: {}", defender_rows_total);
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if let Some(rows) = data["correlations"].as_array() {
            for row in rows.iter().take(20) {
                let exe = row["executable_name"].as_str().unwrap_or_default();
                let sources = row["sources"]
                    .as_array()
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                let last_seen = row["last_seen_utc"].as_str().unwrap_or("n/a");
                println!("[{}] {} ({})", last_seen, exe, sources);
            }
            if rows.len() > 20 {
                println!("... ({} more rows)", rows.len() - 20);
            }
        }
        if let Some(ref w) = warning {
            println!("Warning: {}", w);
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            command_name,
            original_args.clone(),
            EXIT_OK,
            start_time.elapsed().as_millis() as u64,
        )
        .with_data(data);

        if let Some(w) = warning {
            envelope = envelope.warn(w);
        }

        let _ = envelope.write_to_file(json_path);
    }

    std::process::exit(EXIT_OK);
}

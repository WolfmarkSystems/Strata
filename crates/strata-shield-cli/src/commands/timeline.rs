// Extracted from main.rs — run_timeline_command
// TODO: Convert to clap derive args in a future pass

use crate::*;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    about = "Query the case timeline — chronological artifact listing with optional filters."
)]
pub struct TimelineArgs {
    #[arg(short, long)]
    pub case: Option<String>,

    #[arg(short, long)]
    pub db: Option<PathBuf>,

    #[arg(long)]
    pub from: Option<String>,

    #[arg(long)]
    pub to: Option<String>,

    #[arg(short, long, default_value_t = crate::TIMELINE_DEFAULT_LIMIT)]
    pub limit: usize,

    #[arg(long)]
    pub cursor: Option<String>,

    #[arg(long, default_value = "all")]
    pub source: String,

    #[arg(long)]
    pub severity: Option<String>,

    #[arg(long)]
    pub event_type: Option<String>,

    #[arg(long)]
    pub contains: Option<String>,

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
    pub powershell_transcripts_dir: Option<PathBuf>,

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

    #[arg(short, long)]
    pub json: bool,

    #[arg(long)]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: TimelineArgs) {
    let start_time = std::time::Instant::now();
    let original_args = vec![]; // Kept for envelope compatibility

    let case_id = args.case;
    let db_path = args.db;
    let from_utc = args.from;
    let to_utc = args.to;
    let mut limit = args.limit;
    let cursor_raw = args.cursor;
    let source_filter_raw = args.source;
    let severity_filter = args.severity.map(|s| s.to_ascii_lowercase());
    let event_type_filter = args.event_type.map(|s| s.to_ascii_lowercase());
    let contains_filter = args.contains.map(|s| s.to_ascii_lowercase());
    let quiet = args.quiet;
    let json_output = args.json;
    let json_result_path = args.json_result;

    let env_prefetch_path = std::env::var("FORENSIC_PREFETCH_DIR").ok();
    let prefetch_input_explicit = args.prefetch_dir.is_some() || env_prefetch_path.is_some();
    let prefetch_dir = args
        .prefetch_dir
        .or(env_prefetch_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("C:\\Windows\\Prefetch"));

    let env_jumplist_path = std::env::var("FORENSIC_JUMPLIST_PATH").ok();
    let jumplist_input_explicit = args.jumplist_path.is_some() || env_jumplist_path.is_some();
    let jumplist_path = args
        .jumplist_path
        .or(env_jumplist_path.clone().map(PathBuf::from))
        .unwrap_or_else(crate::default_jumplist_path);

    let env_shortcuts_base = std::env::var("FORENSIC_SHORTCUTS_BASE").ok();
    let shortcuts_base = args
        .shortcuts_base
        .or(env_shortcuts_base.clone().map(PathBuf::from))
        .unwrap_or_else(crate::default_shortcuts_base);

    let env_lnk_input = std::env::var("FORENSIC_LNK_PATH").ok();
    let lnk_input_explicit = args.lnk_input.is_some() || env_lnk_input.is_some();
    let lnk_input_path = args
        .lnk_input
        .or(env_lnk_input.clone().map(PathBuf::from))
        .unwrap_or_else(|| {
            if !lnk_input_explicit && env_shortcuts_base.is_some() {
                shortcuts_base.clone()
            } else {
                PathBuf::from("exports").join("shortcuts.json")
            }
        });

    let env_browser_input = std::env::var("FORENSIC_BROWSER_PATH").ok();
    let browser_input_explicit = args.browser_input.is_some() || env_browser_input.is_some();
    let browser_input_path = args
        .browser_input
        .or(env_browser_input.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("browser.json"));

    let env_rdp_input = std::env::var("FORENSIC_RDP_PATH").ok();
    let rdp_input_explicit = args.rdp_input.is_some() || env_rdp_input.is_some();
    let rdp_input_path = args
        .rdp_input
        .or(env_rdp_input.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("rdp.csv"));

    let env_usb_input = std::env::var("FORENSIC_USB_PATH").ok();
    let usb_input_explicit = args.usb_input.is_some() || env_usb_input.is_some();
    let usb_input_path = args
        .usb_input
        .or(env_usb_input.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("usb.json"));

    let env_restore_shadow_input = std::env::var("FORENSIC_RESTORE_SHADOW_PATH").ok();
    let restore_shadow_input_explicit =
        args.restore_shadow_input.is_some() || env_restore_shadow_input.is_some();
    let restore_shadow_input_path = args
        .restore_shadow_input
        .or(env_restore_shadow_input.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("restore_shadow.json"));

    let env_user_activity_input = std::env::var("FORENSIC_USER_ACTIVITY_MRU_PATH").ok();
    let user_activity_input_explicit =
        args.user_activity_input.is_some() || env_user_activity_input.is_some();
    let user_activity_input_path = args
        .user_activity_input
        .or(env_user_activity_input.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("user_activity_mru.json"));

    let env_timeline_correlation_input =
        std::env::var("FORENSIC_TIMELINE_CORRELATION_QA_PATH").ok();
    let timeline_correlation_input_explicit =
        args.timeline_correlation_input.is_some() || env_timeline_correlation_input.is_some();
    let timeline_correlation_input_path = args
        .timeline_correlation_input
        .or(env_timeline_correlation_input.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("timeline_correlation_qa.json"));

    let env_srum_path = std::env::var("FORENSIC_SRUM_PATH").ok();
    let srum_input_explicit = args.srum_input.is_some() || env_srum_path.is_some();
    let srum_path = args
        .srum_input
        .or(env_srum_path.clone().map(PathBuf::from))
        .unwrap_or_else(crate::default_srum_path);

    let env_evtx_security_path = std::env::var("FORENSIC_EVTX_SECURITY_PATH").ok();
    let evtx_security_input_explicit =
        args.evtx_security_input.is_some() || env_evtx_security_path.is_some();
    let evtx_security_path = args
        .evtx_security_input
        .or(env_evtx_security_path.clone().map(PathBuf::from))
        .unwrap_or_else(crate::default_evtx_security_path);

    let env_evtx_sysmon_path = std::env::var("FORENSIC_EVTX_SYSMON_PATH").ok();
    let evtx_sysmon_input_explicit =
        args.evtx_sysmon_input.is_some() || env_evtx_sysmon_path.is_some();
    let evtx_sysmon_path = args
        .evtx_sysmon_input
        .or(env_evtx_sysmon_path.clone().map(PathBuf::from))
        .unwrap_or_else(crate::default_evtx_sysmon_path);

    let env_powershell_history_path = std::env::var("FORENSIC_POWERSHELL_HISTORY").ok();
    let powershell_history_explicit =
        args.powershell_history.is_some() || env_powershell_history_path.is_some();
    let powershell_history_path = args
        .powershell_history
        .or(env_powershell_history_path.clone().map(PathBuf::from))
        .unwrap_or_else(crate::default_powershell_history_path);

    let env_powershell_script_log_path = std::env::var("FORENSIC_POWERSHELL_SCRIPT_LOG").ok();
    let powershell_script_log_explicit =
        args.powershell_script_log.is_some() || env_powershell_script_log_path.is_some();
    let powershell_script_log_path = args
        .powershell_script_log
        .or(env_powershell_script_log_path.clone().map(PathBuf::from))
        .unwrap_or_else(crate::default_powershell_script_log_path);

    let env_powershell_events_path = std::env::var("FORENSIC_POWERSHELL_EVENTS").ok();
    let powershell_events_explicit =
        args.powershell_events.is_some() || env_powershell_events_path.is_some();
    let powershell_events_path = args
        .powershell_events
        .or(env_powershell_events_path.clone().map(PathBuf::from))
        .unwrap_or_else(crate::default_powershell_events_path);

    let env_powershell_transcripts_dir = std::env::var("FORENSIC_POWERSHELL_TRANSCRIPTS").ok();
    let powershell_transcripts_explicit =
        args.powershell_transcripts_dir.is_some() || env_powershell_transcripts_dir.is_some();
    let powershell_transcripts_dir = args
        .powershell_transcripts_dir
        .or(env_powershell_transcripts_dir.clone().map(PathBuf::from))
        .unwrap_or_else(crate::default_powershell_transcripts_dir);

    let env_runmru_reg_path = std::env::var("FORENSIC_RUNMRU_PATH").ok();
    let runmru_reg_explicit = args.runmru_reg.is_some() || env_runmru_reg_path.is_some();
    let runmru_reg_path = args
        .runmru_reg
        .or(env_runmru_reg_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("runmru.reg"));

    let env_opensave_reg_path = std::env::var("FORENSIC_OPENSAVE_PATH").ok();
    let opensave_reg_explicit = args.opensave_reg.is_some() || env_opensave_reg_path.is_some();
    let opensave_reg_path = args
        .opensave_reg
        .or(env_opensave_reg_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("mru2.reg"));

    let env_userassist_reg_path = std::env::var("FORENSIC_USERASSIST_PATH").ok();
    let userassist_reg_explicit =
        args.userassist_reg.is_some() || env_userassist_reg_path.is_some();
    let userassist_reg_path = args
        .userassist_reg
        .or(env_userassist_reg_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("userassist.reg"));

    let env_recentdocs_reg_path = std::env::var("FORENSIC_RECENTDOCS_PATH").ok();
    let recentdocs_reg_explicit =
        args.recentdocs_reg.is_some() || env_recentdocs_reg_path.is_some();
    let recentdocs_reg_path = args
        .recentdocs_reg
        .or(env_recentdocs_reg_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("recentdocs.reg"));

    let env_autorun_reg_path = std::env::var("FORENSIC_AUTORUN_PATH").ok();
    let autorun_reg_explicit = args.autorun_reg.is_some() || env_autorun_reg_path.is_some();
    let autorun_reg_path = args
        .autorun_reg
        .or(env_autorun_reg_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("autorun.reg"));

    let env_bam_reg_path = std::env::var("FORENSIC_BAM_PATH").ok();
    let bam_reg_explicit = args.bam_reg.is_some() || env_bam_reg_path.is_some();
    let bam_reg_path = args
        .bam_reg
        .or(env_bam_reg_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("bam.reg"));

    let env_amcache_reg_path = std::env::var("FORENSIC_AMCACHE_PATH").ok();
    let amcache_reg_explicit = args.amcache_reg.is_some() || env_amcache_reg_path.is_some();
    let amcache_reg_path = args
        .amcache_reg
        .or(env_amcache_reg_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("amcache.reg"));

    let env_shimcache_reg_path = std::env::var("FORENSIC_SHIMCACHE_PATH").ok();
    let shimcache_reg_explicit = args.shimcache_reg.is_some() || env_shimcache_reg_path.is_some();
    let shimcache_reg_path = args
        .shimcache_reg
        .or(env_shimcache_reg_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("appcompat.reg"));

    let env_services_reg_path = std::env::var("FORENSIC_SERVICES_PATH").ok();
    let services_reg_explicit = args.services_reg.is_some() || env_services_reg_path.is_some();
    let services_reg_path = args
        .services_reg
        .or(env_services_reg_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("services.reg"));

    let env_tasks_root_path = std::env::var("FORENSIC_TASKS_ROOT").ok();
    let tasks_root_explicit = args.tasks_root.is_some() || env_tasks_root_path.is_some();
    let tasks_root_path = args
        .tasks_root
        .or(env_tasks_root_path.clone().map(PathBuf::from));

    let env_wmi_persist_path = std::env::var("FORENSIC_WMI_PERSIST_PATH").ok();
    let wmi_persist_explicit = args.wmi_persist_input.is_some() || env_wmi_persist_path.is_some();
    let wmi_persist_path = args
        .wmi_persist_input
        .or(env_wmi_persist_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| {
            PathBuf::from("artifacts")
                .join("wmi")
                .join("persistence.json")
        });

    let env_wmi_traces_path = std::env::var("FORENSIC_WMI_TRACES_PATH").ok();
    let wmi_traces_explicit = args.wmi_traces_input.is_some() || env_wmi_traces_path.is_some();
    let wmi_traces_path = args
        .wmi_traces_input
        .or(env_wmi_traces_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("artifacts").join("wmi").join("traces.json"));

    let env_wmi_instances_path = std::env::var("FORENSIC_WMI_INSTANCES_PATH").ok();
    let wmi_instances_explicit =
        args.wmi_instances_input.is_some() || env_wmi_instances_path.is_some();
    let wmi_instances_path = args
        .wmi_instances_input
        .or(env_wmi_instances_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| {
            PathBuf::from("artifacts")
                .join("wmi")
                .join("instances.json")
        });

    let env_mft_input_path = std::env::var("FORENSIC_MFT_PATH").ok();
    let mft_input_explicit = args.mft_input.is_some() || env_mft_input_path.is_some();
    let mft_input_path = args
        .mft_input
        .or(env_mft_input_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("mft.json"));

    let env_usn_input_path = std::env::var("FORENSIC_USN_PATH").ok();
    let usn_input_explicit = args.usn_input.is_some() || env_usn_input_path.is_some();
    let usn_input_path = args
        .usn_input
        .or(env_usn_input_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("usnjrnl.csv"));

    let env_logfile_input_path = std::env::var("FORENSIC_LOGFILE_PATH").ok();
    let logfile_input_explicit = args.logfile_input.is_some() || env_logfile_input_path.is_some();
    let logfile_input_path = args
        .logfile_input
        .or(env_logfile_input_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("logfile.bin"));

    let env_recycle_input_path = std::env::var("FORENSIC_RECYCLE_BIN_PATH").ok();
    let recycle_input_explicit = args.recycle_input.is_some() || env_recycle_input_path.is_some();
    let recycle_input_path = args
        .recycle_input
        .or(env_recycle_input_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("recycle_bin.json"));

    let env_defender_input_path = std::env::var("FORENSIC_DEFENDER_ARTIFACTS_PATH").ok();
    let defender_input_explicit =
        args.defender_input.is_some() || env_defender_input_path.is_some();
    let defender_input_path = args
        .defender_input
        .or(env_defender_input_path.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("exports").join("defender_artifacts.json"));

    let case_id = match case_id {
        Some(id) => id,
        None => {
            let err_msg = "Error: --case <id> is required".to_string();
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "timeline",
                    original_args.clone(),
                    EXIT_VALIDATION,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("invalid_input")
                .with_hint("Provide --case <case_id> argument");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_VALIDATION);
        }
    };

    let db_path = match db_path {
        Some(path) => path,
        None => {
            let err_msg = "Error: --db <path> is required".to_string();
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "timeline",
                    original_args.clone(),
                    EXIT_VALIDATION,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("invalid_input")
                .with_hint("Provide --db <path> argument");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_VALIDATION);
        }
    };

    if limit == 0 {
        let err_msg = "Error: --limit must be greater than 0".to_string();
        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "timeline",
                original_args.clone(),
                EXIT_VALIDATION,
                start_time.elapsed().as_millis() as u64,
            )
            .error(err_msg.clone())
            .with_error_type("invalid_input")
            .with_hint("Use a positive integer for --limit");
            let _ = envelope.write_to_file(json_path);
        }
        if !quiet {
            println!("{}", err_msg);
        }
        std::process::exit(EXIT_VALIDATION);
    }

    let cursor_offset = match cursor_raw.as_ref() {
        Some(token) => match token.trim().parse::<usize>() {
            Ok(value) => value,
            Err(_) => {
                let err_msg = format!("Error: Invalid --cursor token '{}'", token);
                if let Some(ref json_path) = json_result_path {
                    let envelope = CliResultEnvelope::new(
                        "timeline",
                        original_args.clone(),
                        EXIT_VALIDATION,
                        start_time.elapsed().as_millis() as u64,
                    )
                    .error(err_msg.clone())
                    .with_error_type("invalid_input")
                    .with_hint("Use numeric --cursor token from prior timeline response");
                    let _ = envelope.write_to_file(json_path);
                }
                if !quiet {
                    println!("{}", err_msg);
                }
                std::process::exit(EXIT_VALIDATION);
            }
        },
        None => 0usize,
    };

    let mut warnings: Vec<String> = Vec::new();
    if limit > TIMELINE_MAX_LIMIT {
        warnings.push(format!(
            "Requested limit {} exceeded max {}; clamped.",
            limit, TIMELINE_MAX_LIMIT
        ));
        limit = TIMELINE_MAX_LIMIT;
    }

    let source_filter = match TimelineSourceFilter::parse(&source_filter_raw) {
        Some(source) => source,
        None => {
            let err_msg = format!(
                "Error: Invalid --source '{}'. Use all|activity|evidence|violations|execution|prefetch|jumplist|lnk-shortcuts|browser-forensics|rdp-remote-access|usb-device-history|restore-shadow-copies|user-activity-mru|timeline-correlation-qa|srum|evtx-security|evtx-sysmon|powershell|registry-user-hives|registry-persistence|shimcache|amcache|bam-dam|services-drivers|scheduled-tasks|wmi-persistence|ntfs-mft|usn-journal|ntfs-logfile|recycle-bin|defender-artifacts",
                source_filter_raw
            );
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "timeline",
                    original_args.clone(),
                    EXIT_VALIDATION,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("invalid_input")
                .with_hint("Use --source all|activity|evidence|violations|execution|prefetch|jumplist|lnk-shortcuts|browser-forensics|rdp-remote-access|usb-device-history|restore-shadow-copies|user-activity-mru|timeline-correlation-qa|srum|evtx-security|evtx-sysmon|powershell|registry-user-hives|registry-persistence|shimcache|amcache|bam-dam|services-drivers|scheduled-tasks|wmi-persistence|ntfs-mft|usn-journal|ntfs-logfile|recycle-bin|defender-artifacts");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_VALIDATION);
        }
    };

    if let Some(ref severity) = severity_filter {
        if !matches!(severity.as_str(), "info" | "warn" | "error") {
            let err_msg = format!(
                "Error: Invalid --severity '{}'. Use info|warn|error",
                severity
            );
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "timeline",
                    original_args.clone(),
                    EXIT_VALIDATION,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("invalid_input")
                .with_hint("Use --severity info|warn|error");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_VALIDATION);
        }
    }

    let from_unix = match from_utc.as_ref() {
        Some(value) => match parse_utc_to_unix_seconds(value) {
            Some(ts) => Some(ts),
            None => {
                let err_msg = format!("Error: Invalid --from UTC timestamp '{}'", value);
                if let Some(ref json_path) = json_result_path {
                    let envelope = CliResultEnvelope::new(
                        "timeline",
                        original_args.clone(),
                        EXIT_VALIDATION,
                        start_time.elapsed().as_millis() as u64,
                    )
                    .error(err_msg.clone())
                    .with_error_type("invalid_input")
                    .with_hint("Use RFC3339 UTC timestamp, e.g. 2026-03-07T14:22:10Z");
                    let _ = envelope.write_to_file(json_path);
                }
                if !quiet {
                    println!("{}", err_msg);
                }
                std::process::exit(EXIT_VALIDATION);
            }
        },
        None => None,
    };

    let to_unix = match to_utc.as_ref() {
        Some(value) => match parse_utc_to_unix_seconds(value) {
            Some(ts) => Some(ts),
            None => {
                let err_msg = format!("Error: Invalid --to UTC timestamp '{}'", value);
                if let Some(ref json_path) = json_result_path {
                    let envelope = CliResultEnvelope::new(
                        "timeline",
                        original_args.clone(),
                        EXIT_VALIDATION,
                        start_time.elapsed().as_millis() as u64,
                    )
                    .error(err_msg.clone())
                    .with_error_type("invalid_input")
                    .with_hint("Use RFC3339 UTC timestamp, e.g. 2026-03-07T14:22:10Z");
                    let _ = envelope.write_to_file(json_path);
                }
                if !quiet {
                    println!("{}", err_msg);
                }
                std::process::exit(EXIT_VALIDATION);
            }
        },
        None => None,
    };

    if let (Some(from_ts), Some(to_ts)) = (from_unix, to_unix) {
        if from_ts > to_ts {
            let err_msg = "Error: --from must be less than or equal to --to".to_string();
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "timeline",
                    original_args.clone(),
                    EXIT_VALIDATION,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("invalid_input")
                .with_hint("Use a valid UTC range: from <= to");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_VALIDATION);
        }
    }

    let case_db = match CaseDatabase::open(&case_id, &db_path) {
        Ok(db) => db,
        Err(e) => {
            let err_msg = format!("Error opening database with CaseDatabase: {}", e);
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "timeline",
                    original_args.clone(),
                    EXIT_ERROR,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("database_error")
                .with_hint("Ensure --db points to a valid case SQLite database");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_ERROR);
        }
    };

    let violations_conn = match rusqlite::Connection::open(&db_path) {
        Ok(conn) => conn,
        Err(e) => {
            let err_msg = format!("Error opening database for violations query: {}", e);
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "timeline",
                    original_args.clone(),
                    EXIT_ERROR,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("database_error")
                .with_hint("Ensure --db points to a valid case SQLite database");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_ERROR);
        }
    };

    let mut merged_events: Vec<TimelineMergedEvent> = Vec::new();
    let scan_cap = timeline_scan_limit(limit);
    let since_for_violations = from_unix.map(unix_seconds_to_utc);

    if source_filter.includes_activity() {
        let mut page = 0usize;
        let mut scanned = 0usize;
        let mut stop_source = false;

        while !stop_source {
            let rows = match case_db.get_activity_log_paged(&case_id, page, TIMELINE_PAGE_SIZE) {
                Ok(r) => r,
                Err(e) => {
                    let err_msg = format!("Error querying activity_log: {}", e);
                    if let Some(ref json_path) = json_result_path {
                        let envelope = CliResultEnvelope::new(
                            "timeline",
                            original_args.clone(),
                            EXIT_ERROR,
                            start_time.elapsed().as_millis() as u64,
                        )
                        .error(err_msg.clone())
                        .with_error_type("database_error")
                        .with_hint("Check activity_log table availability");
                        let _ = envelope.write_to_file(json_path);
                    }
                    if !quiet {
                        println!("{}", err_msg);
                    }
                    std::process::exit(EXIT_ERROR);
                }
            };

            if rows.is_empty() {
                break;
            }

            for row in rows {
                scanned += 1;
                if scanned > scan_cap {
                    stop_source = true;
                    break;
                }

                let ts = row.ts_utc;
                if let Some(to_ts) = to_unix {
                    if ts > to_ts {
                        continue;
                    }
                }
                if let Some(from_ts) = from_unix {
                    if ts < from_ts {
                        stop_source = true;
                        break;
                    }
                }

                merged_events.push(TimelineMergedEvent {
                    id: row.id,
                    source: "activity".to_string(),
                    timestamp_utc: unix_seconds_to_utc(ts),
                    timestamp_unix: ts,
                    event_type: row.event_type,
                    event_category: None,
                    summary: row.summary,
                    severity: "info".to_string(),
                    case_id: row.case_id,
                    evidence_id: None,
                    artifact_id: None,
                    actor: Some(row.user_name),
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: None,
                    source_record_id: None,
                    data_json: None,
                });
            }

            page += 1;
        }
    }

    if source_filter.includes_evidence() {
        let mut page = 0usize;
        let mut scanned = 0usize;
        let mut stop_source = false;

        while !stop_source {
            let rows = match case_db.get_evidence_timeline_paged(&case_id, page, TIMELINE_PAGE_SIZE)
            {
                Ok(r) => r,
                Err(e) => {
                    let err_msg = format!("Error querying evidence_timeline: {}", e);
                    if let Some(ref json_path) = json_result_path {
                        let envelope = CliResultEnvelope::new(
                            "timeline",
                            original_args.clone(),
                            EXIT_ERROR,
                            start_time.elapsed().as_millis() as u64,
                        )
                        .error(err_msg.clone())
                        .with_error_type("database_error")
                        .with_hint("Check evidence_timeline table availability");
                        let _ = envelope.write_to_file(json_path);
                    }
                    if !quiet {
                        println!("{}", err_msg);
                    }
                    std::process::exit(EXIT_ERROR);
                }
            };

            if rows.is_empty() {
                break;
            }

            for row in rows {
                scanned += 1;
                if scanned > scan_cap {
                    stop_source = true;
                    break;
                }

                let ts = row.event_time;
                if let Some(to_ts) = to_unix {
                    if ts > to_ts {
                        continue;
                    }
                }
                if let Some(from_ts) = from_unix {
                    if ts < from_ts {
                        stop_source = true;
                        break;
                    }
                }

                let event_type_for_summary = row.event_type.clone();
                let fallback_summary =
                    format!("Evidence timeline event: {}", event_type_for_summary);

                merged_events.push(TimelineMergedEvent {
                    id: row.id,
                    source: "evidence".to_string(),
                    timestamp_utc: unix_seconds_to_utc(ts),
                    timestamp_unix: ts,
                    event_type: row.event_type,
                    event_category: row.event_category,
                    summary: row.description.unwrap_or(fallback_summary),
                    severity: "info".to_string(),
                    case_id: row.case_id,
                    evidence_id: row.evidence_id,
                    artifact_id: row.artifact_id,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: row.source_module,
                    source_record_id: row.source_record_id,
                    data_json: row.data_json,
                });
            }

            page += 1;
        }
    }

    if source_filter.includes_violations() {
        let violations_fetch_limit = scan_cap as u64;
        let violations = match list_integrity_violations(
            &violations_conn,
            &case_id,
            since_for_violations,
            violations_fetch_limit,
        ) {
            Ok(v) => v,
            Err(e) => {
                let err_msg = format!("Error querying integrity violations: {}", e);
                if let Some(ref json_path) = json_result_path {
                    let envelope = CliResultEnvelope::new(
                        "timeline",
                        original_args.clone(),
                        EXIT_ERROR,
                        start_time.elapsed().as_millis() as u64,
                    )
                    .error(err_msg.clone())
                    .with_error_type("database_error")
                    .with_hint("Check integrity_violations table availability");
                    let _ = envelope.write_to_file(json_path);
                }
                if !quiet {
                    println!("{}", err_msg);
                }
                std::process::exit(EXIT_ERROR);
            }
        };

        for violation in violations {
            let ts = match parse_utc_to_unix_seconds(&violation.occurred_utc) {
                Some(value) => value,
                None => continue,
            };

            if let Some(to_ts) = to_unix {
                if ts > to_ts {
                    continue;
                }
            }
            if let Some(from_ts) = from_unix {
                if ts < from_ts {
                    continue;
                }
            }

            let row_key = violation
                .row_key
                .clone()
                .unwrap_or_else(|| "N/A".to_string());
            let summary = format!(
                "{} {} on {} ({})",
                violation.operation, violation.table_name, row_key, violation.reason
            );

            merged_events.push(TimelineMergedEvent {
                id: format!("violation-{}", violation.id),
                source: "violations".to_string(),
                timestamp_utc: unix_seconds_to_utc(ts),
                timestamp_unix: ts,
                event_type: violation.operation.clone(),
                event_category: Some(violation.table_name.clone()),
                summary,
                severity: "warn".to_string(),
                case_id: violation.case_id,
                evidence_id: None,
                artifact_id: None,
                actor: violation.actor,
                table_name: Some(violation.table_name),
                operation: Some(violation.operation),
                reason: Some(violation.reason),
                source_module: None,
                source_record_id: violation.row_key,
                data_json: Some(violation.details_json),
            });
        }
    }

    if source_filter.includes_execution() {
        let prefetch = if prefetch_dir.exists() {
            match scan_prefetch_directory(&prefetch_dir) {
                Ok(rows) => rows,
                Err(e) => {
                    warnings.push(format!(
                        "Could not parse prefetch directory {}: {}",
                        prefetch_dir.display(),
                        e
                    ));
                    Vec::new()
                }
            }
        } else {
            warnings.push(format!(
                "Prefetch directory not found: {}",
                prefetch_dir.display()
            ));
            Vec::new()
        };

        let jumplist = if jumplist_path.exists() {
            match parseautomaticdestinations(&jumplist_path) {
                Ok(rows) => rows.entries,
                Err(e) => {
                    warnings.push(format!(
                        "Could not parse Jump List source {}: {}",
                        jumplist_path.display(),
                        e
                    ));
                    Vec::new()
                }
            }
        } else {
            warnings.push(format!(
                "Jump List source not found: {}",
                jumplist_path.display()
            ));
            Vec::new()
        };

        let shortcuts = if shortcuts_base.exists() {
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

        for row in build_execution_correlations(&prefetch, &jumplist, &shortcuts) {
            let ts = match row.last_seen_unix.or(row.first_seen_unix) {
                Some(value) => value,
                None => continue,
            };

            if let Some(to_ts) = to_unix {
                if ts > to_ts {
                    continue;
                }
            }
            if let Some(from_ts) = from_unix {
                if ts < from_ts {
                    continue;
                }
            }

            let sources_csv = if row.sources.is_empty() {
                "unknown".to_string()
            } else {
                row.sources.join(",")
            };
            let summary = format!(
                "{} observed via {} (hits={})",
                row.executable_name, sources_csv, row.total_hits
            );
            let details = serde_json::json!({
                "sources": row.sources,
                "prefetch_count": row.prefetch_count,
                "jumplist_count": row.jumplist_count,
                "shortcut_count": row.shortcut_count,
                "total_hits": row.total_hits,
                "first_seen_unix": row.first_seen_unix,
                "first_seen_utc": row.first_seen_unix.map(unix_seconds_to_utc),
                "last_seen_unix": row.last_seen_unix,
                "last_seen_utc": row.last_seen_unix.map(unix_seconds_to_utc),
                "latest_prefetch_unix": row.latest_prefetch_unix,
                "latest_jumplist_unix": row.latest_jumplist_unix,
                "latest_shortcut_unix": row.latest_shortcut_unix,
                "sample_paths": row.sample_paths
            });

            merged_events.push(TimelineMergedEvent {
                id: format!(
                    "execution-{}-{}",
                    row.executable_name.to_lowercase().replace(' ', "_"),
                    ts
                ),
                source: "execution".to_string(),
                timestamp_utc: unix_seconds_to_utc(ts),
                timestamp_unix: ts,
                event_type: "recent-execution".to_string(),
                event_category: Some("execution-correlation".to_string()),
                summary,
                severity: "info".to_string(),
                case_id: case_id.clone(),
                evidence_id: None,
                artifact_id: None,
                actor: None,
                table_name: None,
                operation: None,
                reason: None,
                source_module: Some("execution-correlation".to_string()),
                source_record_id: Some(row.executable_name),
                data_json: serde_json::to_string(&details).ok(),
            });
        }
    }

    if source_filter.includes_prefetch() {
        let source_requires_prefetch = matches!(source_filter, TimelineSourceFilter::Prefetch);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if prefetch_dir.exists() {
            let rows = parse_prefetch_records_from_path(&prefetch_dir, scan_cap);
            source_rows = source_rows.saturating_add(rows.len());
            for row in rows {
                let ts = row.last_run_time;
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }

                let process_path = row
                    .files_referenced
                    .iter()
                    .find(|p| executable_name_from_hint(p).is_some())
                    .cloned();
                let summary = if row.run_count > 0 {
                    format!(
                        "Prefetch execution: {} (run_count={})",
                        row.program_name, row.run_count
                    )
                } else {
                    format!("Prefetch execution: {}", row.program_name)
                };
                let details = serde_json::json!({
                    "version": row.version,
                    "program_name": row.program_name,
                    "run_count": row.run_count,
                    "run_times_unix": row.run_times,
                    "files_referenced": row.files_referenced,
                    "directories_referenced": row.directories_referenced,
                    "volumes_referenced": row.volumes_referenced,
                    "process_path": process_path
                });

                merged_events.push(TimelineMergedEvent {
                    id: format!(
                        "prefetch-{}-{}",
                        details["program_name"]
                            .as_str()
                            .unwrap_or("entry")
                            .to_ascii_lowercase()
                            .replace(' ', "_"),
                        ts.unwrap_or(0)
                    ),
                    source: "prefetch".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: "prefetch-execution".to_string(),
                    event_category: Some("execution".to_string()),
                    summary,
                    severity: "info".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("prefetch-fidelity".to_string()),
                    source_record_id: details["program_name"].as_str().map(ToString::to_string),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if prefetch_input_explicit || source_requires_prefetch {
            warnings.push(format!(
                "Prefetch input not found: {}",
                prefetch_dir.display()
            ));
        }

        if source_requires_prefetch && source_rows == 0 {
            warnings.push("No Prefetch rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "Prefetch rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_jumplist() {
        let source_requires_jumplist = matches!(source_filter, TimelineSourceFilter::JumpList);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if jumplist_path.exists() {
            let rows = parse_jumplist_entries_from_path(&jumplist_path, scan_cap);
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row.timestamp;
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }

                let entry_type = match row.entry_type {
                    forensic_engine::classification::JumpListEntryType::Recent => "recent",
                    forensic_engine::classification::JumpListEntryType::Frequent => "frequent",
                    forensic_engine::classification::JumpListEntryType::Tasks => "tasks",
                    forensic_engine::classification::JumpListEntryType::Custom => "custom",
                    forensic_engine::classification::JumpListEntryType::Unknown => "unknown",
                };
                let path_hint = row
                    .target_path
                    .clone()
                    .or_else(|| row.arguments.clone())
                    .unwrap_or_else(|| "unknown target".to_string());
                let summary = format!("Jump List {} entry: {}", entry_type, path_hint);
                let details = serde_json::json!({
                    "entry_type": entry_type,
                    "target_path": row.target_path,
                    "arguments": row.arguments,
                    "app_id": row.app_id,
                    "source_record_id": row.source_record_id,
                    "mru_rank": row.mru_rank
                });

                merged_events.push(TimelineMergedEvent {
                    id: format!(
                        "jumplist-{}-{}",
                        details["app_id"].as_str().unwrap_or("entry"),
                        idx
                    ),
                    source: "jumplist".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: format!("jumplist-{}", entry_type),
                    event_category: Some("execution".to_string()),
                    summary,
                    severity: "info".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("jumplist-fidelity".to_string()),
                    source_record_id: details["source_record_id"].as_u64().map(|v| v.to_string()),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if jumplist_input_explicit || source_requires_jumplist {
            warnings.push(format!(
                "Jump List input not found: {}",
                jumplist_path.display()
            ));
        }

        if source_requires_jumplist && source_rows == 0 {
            warnings.push("No Jump List rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "Jump List rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_lnk_shortcuts() {
        let source_requires_lnk = matches!(source_filter, TimelineSourceFilter::LnkShortcuts);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if lnk_input_path.exists() {
            let rows = parse_lnk_shortcuts_from_path(&lnk_input_path, scan_cap);
            source_rows = source_rows.saturating_add(rows.len());
            for row in rows {
                let ts = row
                    .write_time_unix
                    .or(row.modified_unix)
                    .or(row.created_unix);
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }

                let target = row
                    .target_path
                    .clone()
                    .unwrap_or_else(|| "unknown target".to_string());
                let summary = format!("LNK shortcut target: {}", target);
                let source_id = row.path.clone();
                let details = serde_json::json!({
                    "path": row.path,
                    "target_path": row.target_path,
                    "arguments": row.arguments,
                    "working_directory": row.working_directory,
                    "description": row.description,
                    "created_unix": row.created_unix,
                    "modified_unix": row.modified_unix,
                    "write_time_unix": row.write_time_unix,
                    "access_time_unix": row.access_time_unix,
                    "drive_type": row.drive_type,
                    "drive_serial": row.drive_serial,
                    "machine_id": row.machine_id
                });

                merged_events.push(TimelineMergedEvent {
                    id: format!(
                        "lnk-{}-{}",
                        source_id.to_ascii_lowercase().replace(['\\', '/'], "_"),
                        ts.unwrap_or(0)
                    ),
                    source: "lnk-shortcuts".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: "lnk-shortcut".to_string(),
                    event_category: Some("execution".to_string()),
                    summary,
                    severity: "info".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("lnk-shortcut-fidelity".to_string()),
                    source_record_id: Some(source_id),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if lnk_input_explicit || source_requires_lnk {
            warnings.push(format!("LNK input not found: {}", lnk_input_path.display()));
        }

        if source_requires_lnk && source_rows == 0 {
            warnings.push("No LNK shortcut rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "LNK rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_browser_forensics() {
        let source_requires_browser =
            matches!(source_filter, TimelineSourceFilter::BrowserForensics);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if browser_input_path.exists() {
            let rows = parse_browser_records_from_path(&browser_input_path, scan_cap);
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row.timestamp_unix;
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }

                let browser = row.browser.clone().unwrap_or_else(|| "unknown".to_string());
                let summary = format!("Browser visit ({}): {}", browser, row.url);
                let source_id = row
                    .source_record_id
                    .clone()
                    .unwrap_or_else(|| format!("{}-{}", browser, idx));
                let details = serde_json::json!({
                    "url": row.url,
                    "title": row.title,
                    "browser": row.browser,
                    "timestamp_unix": row.timestamp_unix,
                    "timestamp_utc": row.timestamp_utc,
                    "timestamp_precision": row.timestamp_precision,
                    "user_sid": row.user_sid,
                    "username": row.username,
                    "profile_path": row.profile_path,
                    "process_path": row.process_path,
                    "visit_count": row.visit_count,
                    "source_path": row.source_path
                });

                merged_events.push(TimelineMergedEvent {
                    id: format!("browser-{}-{}", browser, ts.unwrap_or_default()),
                    source: "browser-forensics".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: "browser-visit".to_string(),
                    event_category: Some("web".to_string()),
                    summary,
                    severity: "info".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: row.username,
                    table_name: None,
                    operation: Some("visit".to_string()),
                    reason: None,
                    source_module: Some("browser-forensics".to_string()),
                    source_record_id: Some(source_id),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if browser_input_explicit || source_requires_browser {
            warnings.push(format!(
                "Browser input not found: {}",
                browser_input_path.display()
            ));
        }

        if source_requires_browser && source_rows == 0 {
            warnings.push("No Browser rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "Browser rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_rdp_remote_access() {
        let source_requires_rdp = matches!(source_filter, TimelineSourceFilter::RdpRemoteAccess);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if rdp_input_path.exists() {
            let rows = parse_rdp_records_from_path(&rdp_input_path, scan_cap);
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row
                    .timestamp_unix
                    .or(row.start_time_unix)
                    .or(row.end_time_unix);
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }

                let host = row
                    .target_host
                    .clone()
                    .unwrap_or_else(|| "unknown-host".to_string());
                let summary = format!("RDP session: {}", host);
                let source_id = row
                    .source_record_id
                    .clone()
                    .or_else(|| row.session_id.clone())
                    .unwrap_or_else(|| format!("rdp-{}", idx));
                let details = serde_json::json!({
                    "target_host": row.target_host,
                    "client_address": row.client_address,
                    "username": row.username,
                    "user_sid": row.user_sid,
                    "session_id": row.session_id,
                    "start_time_unix": row.start_time_unix,
                    "end_time_unix": row.end_time_unix,
                    "timestamp_unix": row.timestamp_unix,
                    "timestamp_utc": row.timestamp_utc,
                    "timestamp_precision": row.timestamp_precision,
                    "duration_seconds": row.duration_seconds,
                    "source_kind": row.source_kind,
                    "process_path": row.process_path,
                    "source_path": row.source_path
                });

                merged_events.push(TimelineMergedEvent {
                    id: format!(
                        "rdp-{}-{}",
                        host.to_ascii_lowercase().replace(['\\', '/'], "_"),
                        ts.unwrap_or_default()
                    ),
                    source: "rdp-remote-access".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: "rdp-session".to_string(),
                    event_category: Some("remote-access".to_string()),
                    summary,
                    severity: "info".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: row.username,
                    table_name: None,
                    operation: Some("connect".to_string()),
                    reason: row.client_address,
                    source_module: Some("rdp-remote-access".to_string()),
                    source_record_id: Some(source_id),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if rdp_input_explicit || source_requires_rdp {
            warnings.push(format!("RDP input not found: {}", rdp_input_path.display()));
        }

        if source_requires_rdp && source_rows == 0 {
            warnings.push("No RDP rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "RDP rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_usb_device_history() {
        let source_requires_usb = matches!(source_filter, TimelineSourceFilter::UsbDeviceHistory);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if usb_input_path.exists() {
            let rows = parse_usb_records_from_path(&usb_input_path, scan_cap);
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row
                    .timestamp_unix
                    .or(row.last_connected_unix)
                    .or(row.first_install_unix);
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }

                let vendor = row
                    .vendor_id
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                let product = row
                    .product_id
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                let summary = format!("USB device VID:{} PID:{}", vendor, product);
                let source_id = row
                    .source_record_id
                    .clone()
                    .unwrap_or_else(|| format!("usb-{}", idx));
                let details = serde_json::json!({
                    "vendor_id": row.vendor_id,
                    "product_id": row.product_id,
                    "serial_number": row.serial_number,
                    "friendly_name": row.friendly_name,
                    "first_install_unix": row.first_install_unix,
                    "last_connected_unix": row.last_connected_unix,
                    "timestamp_unix": row.timestamp_unix,
                    "timestamp_utc": row.timestamp_utc,
                    "timestamp_precision": row.timestamp_precision,
                    "user_sid": row.user_sid,
                    "username": row.username,
                    "device_instance_id": row.device_instance_id,
                    "device_class": row.device_class,
                    "source_path": row.source_path
                });

                merged_events.push(TimelineMergedEvent {
                    id: format!(
                        "usb-{}-{}-{}",
                        vendor.to_ascii_lowercase(),
                        product.to_ascii_lowercase(),
                        ts.unwrap_or_default()
                    ),
                    source: "usb-device-history".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: "usb-device".to_string(),
                    event_category: Some("device-history".to_string()),
                    summary,
                    severity: "info".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: row.username,
                    table_name: None,
                    operation: Some("connect".to_string()),
                    reason: row.device_class,
                    source_module: Some("usb-device-history".to_string()),
                    source_record_id: Some(source_id),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if usb_input_explicit || source_requires_usb {
            warnings.push(format!("USB input not found: {}", usb_input_path.display()));
        }

        if source_requires_usb && source_rows == 0 {
            warnings.push("No USB rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "USB rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_restore_shadow_copies() {
        let source_requires_restore =
            matches!(source_filter, TimelineSourceFilter::RestoreShadowCopies);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if restore_shadow_input_path.exists() {
            let rows = parse_restore_shadow_records_from_path(&restore_shadow_input_path, scan_cap);
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row.timestamp_unix;
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }

                let summary = match (&row.name, &row.description) {
                    (Some(name), Some(desc)) if !name.is_empty() && !desc.is_empty() => {
                        format!("{} ({})", name, desc)
                    }
                    (Some(name), _) if !name.is_empty() => name.clone(),
                    _ => format!("{} event", row.source),
                };
                let source_id = row
                    .source_record_id
                    .clone()
                    .or_else(|| row.snapshot_id.clone())
                    .or_else(|| row.restore_point_id.map(|v| v.to_string()))
                    .unwrap_or_else(|| format!("restore-{}", idx));
                let details = serde_json::json!({
                    "source": row.source,
                    "event_type": row.event_type,
                    "restore_point_id": row.restore_point_id,
                    "snapshot_id": row.snapshot_id,
                    "name": row.name,
                    "description": row.description,
                    "restore_point_type": row.restore_point_type,
                    "file_path": row.file_path,
                    "change_type": row.change_type,
                    "status": row.status,
                    "integrity_ok": row.integrity_ok,
                    "timestamp_unix": row.timestamp_unix,
                    "timestamp_utc": row.timestamp_utc,
                    "timestamp_precision": row.timestamp_precision,
                    "user_sid": row.user_sid,
                    "username": row.username,
                    "source_path": row.source_path
                });

                merged_events.push(TimelineMergedEvent {
                    id: format!(
                        "restore-{}-{}",
                        source_id.to_ascii_lowercase().replace(['\\', '/'], "_"),
                        ts.unwrap_or_default()
                    ),
                    source: "restore-shadow-copies".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: row.event_type,
                    event_category: Some("system-restore".to_string()),
                    summary,
                    severity: if row.integrity_ok == Some(false) {
                        "warn".to_string()
                    } else {
                        "info".to_string()
                    },
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: row.username,
                    table_name: None,
                    operation: row.change_type,
                    reason: row.restore_point_type,
                    source_module: Some("restore-shadow-copies".to_string()),
                    source_record_id: Some(source_id),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if restore_shadow_input_explicit || source_requires_restore {
            warnings.push(format!(
                "Restore/Shadow input not found: {}",
                restore_shadow_input_path.display()
            ));
        }

        if source_requires_restore && source_rows == 0 {
            warnings.push("No restore/shadow rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "Restore/shadow rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_user_activity_mru() {
        let source_requires_user_activity =
            matches!(source_filter, TimelineSourceFilter::UserActivityMru);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if user_activity_input_path.exists() {
            let rows =
                parse_user_activity_mru_records_from_path(&user_activity_input_path, scan_cap);
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row.timestamp_unix;
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }

                let summary = row
                    .command
                    .clone()
                    .or_else(|| row.path.clone())
                    .or_else(|| row.program_name.clone())
                    .unwrap_or_else(|| format!("{} activity", row.source));
                let source_id = row
                    .source_record_id
                    .clone()
                    .unwrap_or_else(|| format!("user-activity-{}", idx));
                let details = serde_json::json!({
                    "source": row.source,
                    "event_type": row.event_type,
                    "timestamp_unix": row.timestamp_unix,
                    "timestamp_utc": row.timestamp_utc,
                    "timestamp_precision": row.timestamp_precision,
                    "command": row.command,
                    "path": row.path,
                    "program_name": row.program_name,
                    "executable_name": row.executable_name,
                    "mru_index": row.mru_index,
                    "run_count": row.run_count,
                    "user_sid": row.user_sid,
                    "username": row.username,
                    "source_path": row.source_path
                });

                merged_events.push(TimelineMergedEvent {
                    id: format!(
                        "user-activity-{}-{}",
                        source_id.to_ascii_lowercase().replace(['\\', '/'], "_"),
                        ts.unwrap_or_default()
                    ),
                    source: "user-activity-mru".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: row.event_type,
                    event_category: Some("user-activity".to_string()),
                    summary,
                    severity: if row.run_count.unwrap_or_default() >= 10 {
                        "warn".to_string()
                    } else {
                        "info".to_string()
                    },
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: row.username,
                    table_name: None,
                    operation: None,
                    reason: row.path,
                    source_module: Some("user-activity-mru".to_string()),
                    source_record_id: Some(source_id),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if user_activity_input_explicit || source_requires_user_activity {
            warnings.push(format!(
                "User-activity input not found: {}",
                user_activity_input_path.display()
            ));
        }

        if source_requires_user_activity && source_rows == 0 {
            warnings.push("No user-activity/MRU rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "User-activity/MRU rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_timeline_correlation_qa() {
        let source_requires_timeline_qa =
            matches!(source_filter, TimelineSourceFilter::TimelineCorrelationQa);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if timeline_correlation_input_path.exists() {
            let rows = parse_timeline_correlation_qa_records_from_path(
                &timeline_correlation_input_path,
                scan_cap,
            );
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row.timestamp_unix;
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }

                let source_id = row
                    .source_record_id
                    .clone()
                    .unwrap_or_else(|| format!("timeline-qa-{}", idx));
                let summary = row
                    .summary
                    .clone()
                    .unwrap_or_else(|| format!("{} {}", row.source, row.event_type));
                let details = serde_json::json!({
                    "source": row.source,
                    "event_type": row.event_type,
                    "event_category": row.event_category,
                    "summary": row.summary,
                    "severity": row.severity,
                    "timestamp_unix": row.timestamp_unix,
                    "timestamp_utc": row.timestamp_utc,
                    "timestamp_precision": row.timestamp_precision,
                    "executable_name": row.executable_name,
                    "command": row.command,
                    "path": row.path,
                    "source_module": row.source_module,
                    "source_record_id": row.source_record_id,
                    "case_id": row.case_id,
                    "evidence_id": row.evidence_id,
                    "actor": row.actor,
                    "data_json": row.data_json
                });

                merged_events.push(TimelineMergedEvent {
                    id: format!(
                        "timeline-qa-{}-{}",
                        source_id.to_ascii_lowercase().replace(['\\', '/'], "_"),
                        ts.unwrap_or_default()
                    ),
                    source: "timeline-correlation-qa".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .or_else(|| {
                            details
                                .get("timestamp_utc")
                                .and_then(|v| v.as_str())
                                .map(|v| v.to_string())
                        })
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: details
                        .get("event_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("timeline-event")
                        .to_string(),
                    event_category: details
                        .get("event_category")
                        .and_then(|v| v.as_str())
                        .map(|v| v.to_string())
                        .or_else(|| Some("correlation-qa".to_string())),
                    summary,
                    severity: details
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("info")
                        .to_string(),
                    case_id: case_id.clone(),
                    evidence_id: details
                        .get("evidence_id")
                        .and_then(|v| v.as_str())
                        .map(|v| v.to_string()),
                    artifact_id: None,
                    actor: details
                        .get("actor")
                        .and_then(|v| v.as_str())
                        .map(|v| v.to_string()),
                    table_name: None,
                    operation: None,
                    reason: details
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|v| v.to_string())
                        .or_else(|| {
                            details
                                .get("command")
                                .and_then(|v| v.as_str())
                                .map(|v| v.to_string())
                        }),
                    source_module: details
                        .get("source_module")
                        .and_then(|v| v.as_str())
                        .map(|v| v.to_string())
                        .or_else(|| Some("timeline-correlation-qa".to_string())),
                    source_record_id: Some(source_id),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if timeline_correlation_input_explicit || source_requires_timeline_qa {
            warnings.push(format!(
                "Timeline correlation input not found: {}",
                timeline_correlation_input_path.display()
            ));
        }

        if source_requires_timeline_qa && source_rows == 0 {
            warnings
                .push("No timeline-correlation QA rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "Timeline-correlation QA rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_srum() {
        let source_requires_srum = matches!(source_filter, TimelineSourceFilter::Srum);
        if srum_path.exists() {
            match strata_fs::read(&srum_path) {
                Ok(raw) => {
                    let parsed = parse_srum_records_with_metadata(&raw);
                    let rows = parsed.records;
                    if rows.is_empty() && !raw.is_empty() {
                        warnings.push(format!(
                            "No SRUM rows parsed from {} (expected JSON/CSV export format)",
                            srum_path.display()
                        ));
                    }
                    if (srum_input_explicit || source_requires_srum)
                        && !parsed.metadata.quality_flags.is_empty()
                    {
                        warnings.push(format!(
                            "SRUM quality flags: {}",
                            parsed.metadata.quality_flags.join(",")
                        ));
                    }

                    for row in rows {
                        let ts = row.timestamp_unix.or_else(|| {
                            row.timestamp_utc
                                .as_deref()
                                .and_then(parse_utc_to_unix_seconds)
                        });
                        let Some(ts) = ts else {
                            continue;
                        };

                        if let Some(to_ts) = to_unix {
                            if ts > to_ts {
                                continue;
                            }
                        }
                        if let Some(from_ts) = from_unix {
                            if ts < from_ts {
                                continue;
                            }
                        }

                        let subject = row
                            .app_name
                            .clone()
                            .or_else(|| row.app_id.clone())
                            .or_else(|| row.exe_path.clone())
                            .unwrap_or_else(|| "srum-entry".to_string());
                        let summary = if row.bytes_in.is_some() || row.bytes_out.is_some() {
                            format!(
                                "{} network usage (in={}, out={})",
                                subject,
                                row.bytes_in.unwrap_or(0),
                                row.bytes_out.unwrap_or(0)
                            )
                        } else {
                            format!("{} SRUM usage record", subject)
                        };

                        let provider = row.provider.clone();
                        let record_type = row.record_type.clone();
                        let timestamp_utc = row.timestamp_utc.clone();
                        let timestamp_unix = row.timestamp_unix;
                        let app_id = row.app_id.clone();
                        let app_name = row.app_name.clone();
                        let exe_path = row.exe_path.clone();
                        let user_sid = row.user_sid.clone();
                        let network_interface = row.network_interface.clone();

                        let details = serde_json::json!({
                            "record_id": row.record_id,
                            "provider": provider,
                            "record_type": record_type,
                            "timestamp_utc": timestamp_utc,
                            "timestamp_unix": timestamp_unix,
                            "timestamp_precision": row.timestamp_precision,
                            "app_id": app_id,
                            "app_name": app_name,
                            "exe_path": exe_path,
                            "user_sid": user_sid,
                            "network_interface": network_interface,
                            "bytes_in": row.bytes_in,
                            "bytes_out": row.bytes_out,
                            "packets_in": row.packets_in,
                            "packets_out": row.packets_out
                        });

                        let subject_id = subject.to_lowercase().replace([' ', '\\', '/', ':'], "_");
                        let source_record_id = row
                            .app_id
                            .clone()
                            .or_else(|| row.record_id.map(|v| v.to_string()));
                        let event_id = row
                            .record_id
                            .map(|id| format!("srum-{}", id))
                            .unwrap_or_else(|| format!("srum-{}-{}", subject_id, ts));

                        merged_events.push(TimelineMergedEvent {
                            id: event_id,
                            source: "srum".to_string(),
                            timestamp_utc: unix_seconds_to_utc(ts),
                            timestamp_unix: ts,
                            event_type: row
                                .record_type
                                .unwrap_or_else(|| "srum-record".to_string()),
                            event_category: row.provider,
                            summary,
                            severity: "info".to_string(),
                            case_id: case_id.clone(),
                            evidence_id: None,
                            artifact_id: None,
                            actor: row.user_sid,
                            table_name: None,
                            operation: None,
                            reason: None,
                            source_module: Some("srum".to_string()),
                            source_record_id,
                            data_json: serde_json::to_string(&details).ok(),
                        });
                    }
                }
                Err(e) => warnings.push(format!(
                    "Could not read SRUM input {}: {}",
                    srum_path.display(),
                    e
                )),
            }
        } else if srum_input_explicit || source_requires_srum {
            warnings.push(format!("SRUM input not found: {}", srum_path.display()));
        }
    }

    if source_filter.includes_evtx_security() {
        let source_requires_evtx_security =
            matches!(source_filter, TimelineSourceFilter::EvtxSecurity);
        if evtx_security_path.exists() {
            match parse_security_log_with_metadata(&evtx_security_path) {
                Ok(parsed) => {
                    if parsed.summary.entries.is_empty() {
                        warnings.push(format!(
                            "No EVTX security rows parsed from {}",
                            evtx_security_path.display()
                        ));
                    }
                    if (evtx_security_input_explicit || source_requires_evtx_security)
                        && !parsed.metadata.quality_flags.is_empty()
                    {
                        warnings.push(format!(
                            "EVTX security quality flags: {}",
                            parsed.metadata.quality_flags.join(",")
                        ));
                    }

                    for row in parsed.summary.entries {
                        let Some(ts) = row.timestamp else {
                            continue;
                        };

                        if let Some(to_ts) = to_unix {
                            if ts > to_ts {
                                continue;
                            }
                        }
                        if let Some(from_ts) = from_unix {
                            if ts < from_ts {
                                continue;
                            }
                        }

                        let severity = if row.level <= 2 {
                            "error".to_string()
                        } else if row.level == 3 {
                            "warn".to_string()
                        } else {
                            "info".to_string()
                        };
                        let event_type = format!("event-{}", row.event_id);
                        let summary = row
                            .semantic_summary
                            .clone()
                            .or(row.message.clone())
                            .unwrap_or_else(|| {
                                format!("Security event {} from {}", row.event_id, row.source)
                            });
                        let details = serde_json::json!({
                            "event_id": row.event_id,
                            "level": row.level,
                            "level_name": row.level_name,
                            "source": row.source,
                            "channel": row.channel,
                            "record_id": row.record_id,
                            "task": row.task,
                            "opcode": row.opcode,
                            "keywords": row.keywords,
                            "process_id": row.process_id,
                            "thread_id": row.thread_id,
                            "event_data": row.event_data
                        });
                        let event_id = row
                            .record_id
                            .map(|id| format!("evtx-security-{}", id))
                            .unwrap_or_else(|| format!("evtx-security-{}-{}", row.event_id, ts));
                        merged_events.push(TimelineMergedEvent {
                            id: event_id,
                            source: "evtx-security".to_string(),
                            timestamp_utc: unix_seconds_to_utc(ts),
                            timestamp_unix: ts,
                            event_type,
                            event_category: row.semantic_category.or(row.channel),
                            summary,
                            severity,
                            case_id: case_id.clone(),
                            evidence_id: None,
                            artifact_id: None,
                            actor: row.user,
                            table_name: None,
                            operation: None,
                            reason: None,
                            source_module: Some("evtx-security".to_string()),
                            source_record_id: row.record_id.map(|v| v.to_string()),
                            data_json: serde_json::to_string(&details).ok(),
                        });
                    }
                }
                Err(e) => warnings.push(format!(
                    "Could not parse EVTX security input {}: {}",
                    evtx_security_path.display(),
                    e
                )),
            }
        } else if evtx_security_input_explicit || source_requires_evtx_security {
            warnings.push(format!(
                "EVTX security input not found: {}",
                evtx_security_path.display()
            ));
        }
    }

    if source_filter.includes_evtx_sysmon() {
        let source_requires_evtx_sysmon = matches!(source_filter, TimelineSourceFilter::EvtxSysmon);
        if evtx_sysmon_path.exists() {
            match parse_system_log_with_metadata(&evtx_sysmon_path) {
                Ok(parsed) => {
                    if parsed.entries.is_empty() {
                        warnings.push(format!(
                            "No EVTX sysmon rows parsed from {}",
                            evtx_sysmon_path.display()
                        ));
                    }
                    if (evtx_sysmon_input_explicit || source_requires_evtx_sysmon)
                        && !parsed.metadata.quality_flags.is_empty()
                    {
                        warnings.push(format!(
                            "EVTX sysmon quality flags: {}",
                            parsed.metadata.quality_flags.join(",")
                        ));
                    }

                    for row in parsed.entries {
                        let Some(ts) = row.timestamp else {
                            continue;
                        };

                        if let Some(to_ts) = to_unix {
                            if ts > to_ts {
                                continue;
                            }
                        }
                        if let Some(from_ts) = from_unix {
                            if ts < from_ts {
                                continue;
                            }
                        }

                        let severity =
                            if row.event_id == 8 || row.event_id == 10 || row.event_id == 13 {
                                "warn".to_string()
                            } else if row.level <= 2 {
                                "error".to_string()
                            } else {
                                "info".to_string()
                            };
                        let event_type = format!("sysmon-{}", row.event_id);
                        let summary = row
                            .semantic_summary
                            .clone()
                            .or(row.message.clone())
                            .unwrap_or_else(|| {
                                format!("Sysmon event {} from {}", row.event_id, row.source)
                            });
                        let details = serde_json::json!({
                            "event_id": row.event_id,
                            "level": row.level,
                            "level_name": row.level_name,
                            "source": row.source,
                            "channel": row.channel,
                            "record_id": row.record_id,
                            "task": row.task,
                            "opcode": row.opcode,
                            "keywords": row.keywords,
                            "process_id": row.process_id,
                            "thread_id": row.thread_id,
                            "event_data": row.event_data
                        });
                        let event_id = row
                            .record_id
                            .map(|id| format!("evtx-sysmon-{}", id))
                            .unwrap_or_else(|| format!("evtx-sysmon-{}-{}", row.event_id, ts));
                        merged_events.push(TimelineMergedEvent {
                            id: event_id,
                            source: "evtx-sysmon".to_string(),
                            timestamp_utc: unix_seconds_to_utc(ts),
                            timestamp_unix: ts,
                            event_type,
                            event_category: row.semantic_category.or(row.channel),
                            summary,
                            severity,
                            case_id: case_id.clone(),
                            evidence_id: None,
                            artifact_id: None,
                            actor: row.user,
                            table_name: None,
                            operation: None,
                            reason: None,
                            source_module: Some("evtx-sysmon".to_string()),
                            source_record_id: row.record_id.map(|v| v.to_string()),
                            data_json: serde_json::to_string(&details).ok(),
                        });
                    }
                }
                Err(e) => warnings.push(format!(
                    "Could not parse EVTX sysmon input {}: {}",
                    evtx_sysmon_path.display(),
                    e
                )),
            }
        } else if evtx_sysmon_input_explicit || source_requires_evtx_sysmon {
            warnings.push(format!(
                "EVTX sysmon input not found: {}",
                evtx_sysmon_path.display()
            ));
        }
    }

    if source_filter.includes_powershell() {
        let source_requires_powershell = matches!(source_filter, TimelineSourceFilter::Powershell);
        let mut source_rows = 0usize;

        if powershell_history_path.exists() {
            let history_rows = parse_powershell_history_file(&powershell_history_path);
            source_rows = source_rows.saturating_add(history_rows.len());
        } else if powershell_history_explicit || source_requires_powershell {
            warnings.push(format!(
                "PowerShell history input not found: {}",
                powershell_history_path.display()
            ));
        }

        if powershell_script_log_path.exists() {
            let script_rows = parse_powershell_script_log_file(&powershell_script_log_path);
            source_rows = source_rows.saturating_add(script_rows.len());
            for row in script_rows {
                let ts = row.timestamp as i64;
                if ts <= 0 {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if ts > to_ts {
                        continue;
                    }
                }
                if let Some(from_ts) = from_unix {
                    if ts < from_ts {
                        continue;
                    }
                }

                let text = format!("{} {}", row.script_path, row.parameters)
                    .trim()
                    .to_string();
                let summary = if row.script_path.is_empty() {
                    "PowerShell script execution".to_string()
                } else {
                    format!("PowerShell script execution: {}", row.script_path)
                };

                let details = serde_json::json!({
                    "timestamp_unix": row.timestamp,
                    "script_path": row.script_path,
                    "parameters": row.parameters,
                    "result": row.result
                });

                merged_events.push(TimelineMergedEvent {
                    id: format!("powershell-script-log-{}", ts),
                    source: "powershell".to_string(),
                    timestamp_utc: unix_seconds_to_utc(ts),
                    timestamp_unix: ts,
                    event_type: "powershell-script-log".to_string(),
                    event_category: Some("script-log".to_string()),
                    summary,
                    severity: powershell_severity(&text).to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("powershell-script-log".to_string()),
                    source_record_id: None,
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if powershell_script_log_explicit || source_requires_powershell {
            warnings.push(format!(
                "PowerShell script log input not found: {}",
                powershell_script_log_path.display()
            ));
        }

        if powershell_events_path.exists() {
            let ps_events = parse_powershell_events_file(&powershell_events_path);
            source_rows = source_rows.saturating_add(ps_events.len());
            for (idx, row) in ps_events.into_iter().enumerate() {
                let ts = row.timestamp as i64;
                if ts <= 0 {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if ts > to_ts {
                        continue;
                    }
                }
                if let Some(from_ts) = from_unix {
                    if ts < from_ts {
                        continue;
                    }
                }

                let details = serde_json::json!({
                    "timestamp_unix": row.timestamp,
                    "script": row.script
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("powershell-event-{}-{}", ts, idx),
                    source: "powershell".to_string(),
                    timestamp_utc: unix_seconds_to_utc(ts),
                    timestamp_unix: ts,
                    event_type: "powershell-event".to_string(),
                    event_category: Some("event".to_string()),
                    summary: "PowerShell event record".to_string(),
                    severity: powershell_severity(&row.script).to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("powershell-events".to_string()),
                    source_record_id: None,
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if powershell_events_explicit || source_requires_powershell {
            warnings.push(format!(
                "PowerShell events input not found: {}",
                powershell_events_path.display()
            ));
        }

        if powershell_transcripts_dir.exists() {
            let transcript_rows = parse_powershell_transcripts_dir(&powershell_transcripts_dir);
            source_rows = source_rows.saturating_add(transcript_rows.len());
            for row in transcript_rows {
                let ts = row.start_time as i64;
                if ts <= 0 {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if ts > to_ts {
                        continue;
                    }
                }
                if let Some(from_ts) = from_unix {
                    if ts < from_ts {
                        continue;
                    }
                }

                let details = serde_json::json!({
                    "path": row.path,
                    "start_time": row.start_time,
                    "end_time": row.end_time,
                    "command_count": row.command_count
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("powershell-transcript-{}", ts),
                    source: "powershell".to_string(),
                    timestamp_utc: unix_seconds_to_utc(ts),
                    timestamp_unix: ts,
                    event_type: "powershell-transcript".to_string(),
                    event_category: Some("transcript".to_string()),
                    summary: "PowerShell transcript session".to_string(),
                    severity: "info".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("powershell-transcript".to_string()),
                    source_record_id: None,
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if powershell_transcripts_explicit || source_requires_powershell {
            warnings.push(format!(
                "PowerShell transcripts input not found: {}",
                powershell_transcripts_dir.display()
            ));
        }

        if source_requires_powershell && source_rows == 0 {
            warnings.push("No PowerShell artifacts found from configured inputs.".to_string());
        }
    }

    if source_filter.includes_registry_user_hives() {
        let source_requires_registry_user_hives =
            matches!(source_filter, TimelineSourceFilter::RegistryUserHives);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if runmru_reg_path.exists() {
            source_rows = source_rows.saturating_add(
                forensic_engine::classification::regmru::get_run_mru_from_reg(&runmru_reg_path)
                    .len(),
            );
        } else if runmru_reg_explicit || source_requires_registry_user_hives {
            warnings.push(format!(
                "RunMRU input not found: {}",
                runmru_reg_path.display()
            ));
        }

        if opensave_reg_path.exists() {
            source_rows = source_rows.saturating_add(
                forensic_engine::classification::regmru2::get_open_save_mru_from_reg(
                    &opensave_reg_path,
                )
                .len(),
            );
        } else if opensave_reg_explicit || source_requires_registry_user_hives {
            warnings.push(format!(
                "OpenSaveMRU input not found: {}",
                opensave_reg_path.display()
            ));
        }

        if userassist_reg_path.exists() {
            let rows = forensic_engine::classification::reguserassist::get_user_assist_from_reg(
                &userassist_reg_path,
            );
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let Some(ts) = row.last_run.map(|v| v as i64) else {
                    continue;
                };
                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                let summary = format!(
                    "UserAssist: {} (run_count={})",
                    row.program_name, row.run_count
                );
                let details = serde_json::json!({
                    "program_name": row.program_name,
                    "run_count": row.run_count,
                    "last_run_utc": row.last_run_utc,
                    "source": "userassist"
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("registry-user-hives-userassist-{}-{}", ts, idx),
                    source: "registry-user-hives".to_string(),
                    timestamp_utc: unix_seconds_to_utc(ts),
                    timestamp_unix: ts,
                    event_type: "registry-userassist".to_string(),
                    event_category: Some("userassist".to_string()),
                    summary,
                    severity: if row.run_count >= 10 {
                        "warn".to_string()
                    } else {
                        "info".to_string()
                    },
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("registry-userassist".to_string()),
                    source_record_id: None,
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if userassist_reg_explicit || source_requires_registry_user_hives {
            warnings.push(format!(
                "UserAssist input not found: {}",
                userassist_reg_path.display()
            ));
        }

        if recentdocs_reg_path.exists() {
            let rows = forensic_engine::classification::regmru::get_recent_docs_from_reg(
                &recentdocs_reg_path,
            );
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let Some(ts) = row.timestamp.map(|v| v as i64) else {
                    continue;
                };
                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                let details = serde_json::json!({
                    "name": row.name,
                    "source": "recentdocs"
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("registry-user-hives-recentdocs-{}-{}", ts, idx),
                    source: "registry-user-hives".to_string(),
                    timestamp_utc: unix_seconds_to_utc(ts),
                    timestamp_unix: ts,
                    event_type: "registry-recentdocs".to_string(),
                    event_category: Some("recentdocs".to_string()),
                    summary: "RecentDocs entry".to_string(),
                    severity: "info".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("registry-recentdocs".to_string()),
                    source_record_id: None,
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if recentdocs_reg_explicit || source_requires_registry_user_hives {
            warnings.push(format!(
                "RecentDocs input not found: {}",
                recentdocs_reg_path.display()
            ));
        }

        if source_requires_registry_user_hives && source_rows == 0 {
            warnings
                .push("No registry user-hive artifacts found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "Registry user-hive artifacts were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_registry_persistence() {
        let source_requires_registry_persistence =
            matches!(source_filter, TimelineSourceFilter::RegistryPersistence);
        let mut source_rows = 0usize;

        let autoruns = if autorun_reg_path.exists() {
            forensic_engine::classification::autorun::get_auto_run_keys_from_reg(&autorun_reg_path)
        } else {
            if autorun_reg_explicit || source_requires_registry_persistence {
                warnings.push(format!(
                    "Autorun input not found: {}",
                    autorun_reg_path.display()
                ));
            }
            Vec::new()
        };

        let bam = if bam_reg_path.exists() {
            forensic_engine::classification::regbam::get_bam_state_from_reg(&bam_reg_path)
        } else {
            if bam_reg_explicit || source_requires_registry_persistence {
                warnings.push(format!(
                    "BAM/DAM input not found: {}",
                    bam_reg_path.display()
                ));
            }
            Vec::new()
        };

        let tasks = if let Some(root) = tasks_root_path.as_ref() {
            if root.exists() {
                match parse_scheduled_tasks_xml(root) {
                    Ok(rows) => rows,
                    Err(e) => {
                        warnings.push(format!(
                            "Could not parse scheduled tasks from {}: {}",
                            root.display(),
                            e
                        ));
                        Vec::new()
                    }
                }
            } else {
                if tasks_root_explicit || source_requires_registry_persistence {
                    warnings.push(format!(
                        "Scheduled tasks root not found: {}",
                        root.display()
                    ));
                }
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let amcache = if amcache_reg_path.exists() {
            forensic_engine::classification::amcache::get_amcache_file_entries_from_reg(
                &amcache_reg_path,
            )
            .unwrap_or_else(|_| Vec::new())
        } else {
            if amcache_reg_explicit || source_requires_registry_persistence {
                warnings.push(format!(
                    "Amcache input not found: {}",
                    amcache_reg_path.display()
                ));
            }
            Vec::new()
        };

        let rows = build_persistence_correlations_with_amcache(&autoruns, &tasks, &bam, &amcache);
        source_rows = source_rows.saturating_add(rows.len());
        for (idx, row) in rows.into_iter().enumerate() {
            let Some(ts) = row.latest_execution_unix.map(|v| v as i64) else {
                continue;
            };
            let summary = format!(
                "Registry persistence correlation: {} [{}]",
                row.executable_path, row.overall_confidence
            );
            let details = serde_json::json!({
                "executable_path": row.executable_path,
                "sources": row.sources,
                "autorun_count": row.autorun_count,
                "scheduled_task_count": row.scheduled_task_count,
                "bam_count": row.bam_count,
                "dam_count": row.dam_count,
                "amcache_count": row.amcache_count,
                "overall_confidence": row.overall_confidence,
                "correlation_reasons": row.reason_codes
            });
            merged_events.push(TimelineMergedEvent {
                id: format!("registry-persistence-{}-{}", ts, idx),
                source: "registry-persistence".to_string(),
                timestamp_utc: unix_seconds_to_utc(ts),
                timestamp_unix: ts,
                event_type: "registry-persistence-correlation".to_string(),
                event_category: Some("persistence".to_string()),
                summary,
                severity: if row.overall_confidence.eq_ignore_ascii_case("high") {
                    "warn".to_string()
                } else {
                    "info".to_string()
                },
                case_id: case_id.clone(),
                evidence_id: None,
                artifact_id: None,
                actor: None,
                table_name: None,
                operation: None,
                reason: None,
                source_module: Some("registry-persistence".to_string()),
                source_record_id: None,
                data_json: serde_json::to_string(&details).ok(),
            });
        }

        if source_requires_registry_persistence && source_rows == 0 {
            warnings.push("No registry persistence rows found from configured inputs.".to_string());
        }
    }

    if source_filter.includes_shimcache() {
        let source_requires_shimcache = matches!(source_filter, TimelineSourceFilter::Shimcache);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if shimcache_reg_path.exists() {
            let rows = forensic_engine::classification::regbam::get_shim_cache_from_reg(
                &shimcache_reg_path,
            );
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let Some(ts) = row.last_modified.map(|v| v as i64) else {
                    continue;
                };
                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                let summary = format!("ShimCache: {}", row.path);
                let details = serde_json::json!({
                    "path": row.path,
                    "source_key": row.source_key,
                    "last_modified_utc": row.last_modified_utc
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("shimcache-{}-{}", ts, idx),
                    source: "shimcache".to_string(),
                    timestamp_utc: unix_seconds_to_utc(ts),
                    timestamp_unix: ts,
                    event_type: "shimcache-entry".to_string(),
                    event_category: Some("execution".to_string()),
                    summary,
                    severity: "info".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("shimcache-deep".to_string()),
                    source_record_id: None,
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if shimcache_reg_explicit || source_requires_shimcache {
            warnings.push(format!(
                "ShimCache input not found: {}",
                shimcache_reg_path.display()
            ));
        }

        if source_requires_shimcache && source_rows == 0 {
            warnings.push("No ShimCache rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "ShimCache rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_amcache() {
        let source_requires_amcache = matches!(source_filter, TimelineSourceFilter::Amcache);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if amcache_reg_path.exists() {
            let rows = forensic_engine::classification::amcache::get_amcache_file_entries_from_reg(
                &amcache_reg_path,
            )
            .unwrap_or_else(|_| Vec::new());
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts_opt = if row.last_modified > 0 {
                    Some(row.last_modified as i64)
                } else if row.created > 0 {
                    Some(row.created as i64)
                } else {
                    None
                };
                let Some(ts) = ts_opt else {
                    continue;
                };
                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                let summary = if row.file_path.is_empty() {
                    "Amcache entry".to_string()
                } else {
                    format!("Amcache: {}", row.file_path)
                };
                let details = serde_json::json!({
                    "file_path": row.file_path,
                    "sha1": row.sha1,
                    "program_id": row.program_id,
                    "last_modified_utc": row.last_modified_utc,
                    "created_utc": row.created_utc
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("amcache-{}-{}", ts, idx),
                    source: "amcache".to_string(),
                    timestamp_utc: unix_seconds_to_utc(ts),
                    timestamp_unix: ts,
                    event_type: "amcache-entry".to_string(),
                    event_category: Some("execution".to_string()),
                    summary,
                    severity: "info".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("amcache-deep".to_string()),
                    source_record_id: None,
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if amcache_reg_explicit || source_requires_amcache {
            warnings.push(format!(
                "Amcache input not found: {}",
                amcache_reg_path.display()
            ));
        }

        if source_requires_amcache && source_rows == 0 {
            warnings.push("No Amcache rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "Amcache rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_bam_dam() {
        let source_requires_bam_dam = matches!(source_filter, TimelineSourceFilter::BamDam);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if bam_reg_path.exists() {
            let rows =
                forensic_engine::classification::regbam::get_bam_state_from_reg(&bam_reg_path);
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let Some(ts) = row.last_execution.map(|v| v as i64) else {
                    continue;
                };
                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                let source_kind = if row.source.eq_ignore_ascii_case("dam") {
                    "dam"
                } else {
                    "bam"
                };
                let summary = format!(
                    "{} execution: {}",
                    source_kind.to_uppercase(),
                    row.program_path
                );
                let details = serde_json::json!({
                    "program_path": row.program_path,
                    "actor_sid": row.actor_sid,
                    "last_execution_utc": row.last_execution_utc,
                    "source_kind": source_kind
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("bam-dam-{}-{}", ts, idx),
                    source: "bam-dam".to_string(),
                    timestamp_utc: unix_seconds_to_utc(ts),
                    timestamp_unix: ts,
                    event_type: format!("{}-activity", source_kind),
                    event_category: Some("execution".to_string()),
                    summary,
                    severity: if source_kind == "dam" {
                        "warn".to_string()
                    } else {
                        "info".to_string()
                    },
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: row.actor_sid.clone(),
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("bam-dam-activity".to_string()),
                    source_record_id: None,
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if bam_reg_explicit || source_requires_bam_dam {
            warnings.push(format!(
                "BAM/DAM input not found: {}",
                bam_reg_path.display()
            ));
        }

        if source_requires_bam_dam && source_rows == 0 {
            warnings.push("No BAM/DAM rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "BAM/DAM rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_services_drivers() {
        let source_requires_services =
            matches!(source_filter, TimelineSourceFilter::ServicesDrivers);
        let mut source_rows = 0usize;
        let with_timestamp_rows = 0usize;

        if services_reg_path.exists() {
            let config_rows =
                forensic_engine::classification::regservice::get_services_config_from_reg(
                    &services_reg_path,
                );
            source_rows = source_rows.saturating_add(config_rows.len());
            if from_unix.is_none() && to_unix.is_none() {
                for (idx, row) in config_rows.into_iter().enumerate() {
                    let summary = format!("Service config: {}", row.name);
                    let details = serde_json::json!({
                        "display_name": row.display_name,
                        "start_type": row.start_type,
                        "service_type": row.service_type,
                        "service_account": row.service_account,
                        "image_path": row.path,
                        "description": row.description
                    });
                    merged_events.push(TimelineMergedEvent {
                        id: format!("services-drivers-config-{}", idx),
                        source: "services-drivers".to_string(),
                        timestamp_utc: "unknown".to_string(),
                        timestamp_unix: 0,
                        event_type: "service-config".to_string(),
                        event_category: Some("persistence".to_string()),
                        summary,
                        severity: "info".to_string(),
                        case_id: case_id.clone(),
                        evidence_id: None,
                        artifact_id: None,
                        actor: None,
                        table_name: None,
                        operation: None,
                        reason: None,
                        source_module: Some("services-drivers-artifacts".to_string()),
                        source_record_id: None,
                        data_json: serde_json::to_string(&details).ok(),
                    });
                }
            }

            let dll_rows =
                forensic_engine::classification::regservice::get_service_dll_entries_from_reg(
                    &services_reg_path,
                );
            source_rows = source_rows.saturating_add(dll_rows.len());
            if from_unix.is_none() && to_unix.is_none() {
                for (idx, row) in dll_rows.into_iter().enumerate() {
                    let summary = format!("Service DLL: {} -> {}", row.service, row.dll_path);
                    let details = serde_json::json!({
                        "service": row.service,
                        "dll_path": row.dll_path,
                        "service_main": row.service_main,
                        "host_image_path": row.host_image_path,
                        "suspicious": row.suspicious,
                        "reasons": row.reasons
                    });
                    merged_events.push(TimelineMergedEvent {
                        id: format!("services-drivers-dll-{}", idx),
                        source: "services-drivers".to_string(),
                        timestamp_utc: "unknown".to_string(),
                        timestamp_unix: 0,
                        event_type: "service-dll-entry".to_string(),
                        event_category: Some("persistence".to_string()),
                        summary,
                        severity: if row.suspicious {
                            "warn".to_string()
                        } else {
                            "info".to_string()
                        },
                        case_id: case_id.clone(),
                        evidence_id: None,
                        artifact_id: None,
                        actor: None,
                        table_name: None,
                        operation: None,
                        reason: None,
                        source_module: Some("services-drivers-artifacts".to_string()),
                        source_record_id: None,
                        data_json: serde_json::to_string(&details).ok(),
                    });
                }
            }
        } else if services_reg_explicit || source_requires_services {
            warnings.push(format!(
                "Services/Drivers input not found: {}",
                services_reg_path.display()
            ));
        }

        if source_requires_services && source_rows == 0 {
            warnings.push("No services/drivers rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "Services/drivers rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_scheduled_tasks() {
        let source_requires_tasks = matches!(source_filter, TimelineSourceFilter::ScheduledTasks);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;
        let tasks_root = tasks_root_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("exports").join("tasks"));

        if tasks_root.exists() {
            let mut rows = parse_scheduled_tasks_xml(&tasks_root).unwrap_or_else(|_| Vec::new());
            if rows.is_empty() {
                rows = forensic_engine::classification::scheduledtasks::parse_scheduled_tasks_text_fallback(
                    &tasks_root,
                );
            }
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row.last_run_time.or(row.next_run_time);
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }
                let summary = if row.name.is_empty() {
                    "Scheduled task entry".to_string()
                } else {
                    format!("Scheduled task: {}", row.name)
                };
                let details = serde_json::json!({
                    "task_path": row.path,
                    "author": row.author,
                    "description": row.description,
                    "action_count": row.actions.len(),
                    "trigger_count": row.triggers.len(),
                    "next_run_time": row.next_run_time,
                    "last_run_time": row.last_run_time
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("scheduled-task-{}-{}", ts.unwrap_or(0), idx),
                    source: "scheduled-tasks".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: "scheduled-task".to_string(),
                    event_category: Some("persistence".to_string()),
                    summary,
                    severity: if matches!(
                        row.state,
                        forensic_engine::classification::TaskState::Disabled
                    ) {
                        "warn".to_string()
                    } else {
                        "info".to_string()
                    },
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: row.author.clone(),
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("scheduled-tasks-artifacts".to_string()),
                    source_record_id: None,
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if tasks_root_explicit || source_requires_tasks {
            warnings.push(format!(
                "Scheduled tasks root not found: {}",
                tasks_root.display()
            ));
        }

        if source_requires_tasks && source_rows == 0 {
            warnings.push("No scheduled-task rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "Scheduled-task rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_wmi_persistence() {
        let source_requires_wmi = matches!(source_filter, TimelineSourceFilter::WmiPersistence);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if wmi_persist_path.exists() {
            let rows = forensic_engine::classification::wmipersist::get_wmi_persistence_from_path(
                &wmi_persist_path,
            );
            source_rows = source_rows.saturating_add(rows.len());
            if from_unix.is_none() && to_unix.is_none() {
                for (idx, row) in rows.into_iter().enumerate() {
                    let consumer = row.consumer;
                    let filter = row.filter;
                    let summary = if !consumer.trim().is_empty() {
                        format!("WMI persistence binding: {}", consumer)
                    } else if !filter.trim().is_empty() {
                        format!("WMI persistence filter: {}", filter)
                    } else {
                        "WMI persistence binding".to_string()
                    };
                    let details = serde_json::json!({
                        "consumer": consumer,
                        "filter": filter
                    });
                    merged_events.push(TimelineMergedEvent {
                        id: format!("wmi-persist-{}", idx),
                        source: "wmi-persistence".to_string(),
                        timestamp_utc: "unknown".to_string(),
                        timestamp_unix: 0,
                        event_type: "wmi-persistence-binding".to_string(),
                        event_category: Some("persistence".to_string()),
                        summary,
                        severity: "warn".to_string(),
                        case_id: case_id.clone(),
                        evidence_id: None,
                        artifact_id: None,
                        actor: None,
                        table_name: None,
                        operation: None,
                        reason: None,
                        source_module: Some("wmi-persistence-activity".to_string()),
                        source_record_id: None,
                        data_json: serde_json::to_string(&details).ok(),
                    });
                }
            }
        } else if wmi_persist_explicit || source_requires_wmi {
            warnings.push(format!(
                "WMI persistence input not found: {}",
                wmi_persist_path.display()
            ));
        }

        if wmi_traces_path.exists() {
            let rows = forensic_engine::classification::wmitrace::get_wmi_traces_from_path(
                &wmi_traces_path,
            );
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = if row.timestamp > 0 {
                    Some(row.timestamp as i64)
                } else {
                    None
                };
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }
                let namespace = row.namespace;
                let summary = if namespace.trim().is_empty() {
                    "WMI trace".to_string()
                } else {
                    format!("WMI trace: {}", namespace)
                };
                let details = serde_json::json!({
                    "namespace": namespace
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("wmi-trace-{}-{}", ts.unwrap_or(0), idx),
                    source: "wmi-persistence".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: "wmi-trace".to_string(),
                    event_category: Some("activity".to_string()),
                    summary,
                    severity: "info".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("wmi-persistence-activity".to_string()),
                    source_record_id: None,
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if wmi_traces_explicit || source_requires_wmi {
            warnings.push(format!(
                "WMI traces input not found: {}",
                wmi_traces_path.display()
            ));
        }

        if wmi_instances_path.exists() {
            let rows = forensic_engine::classification::wmiinst::get_wmi_class_instances_from_path(
                &wmi_instances_path,
            );
            source_rows = source_rows.saturating_add(rows.len());
            if from_unix.is_none() && to_unix.is_none() {
                for (idx, row) in rows.into_iter().enumerate() {
                    let summary = format!("WMI class instance: {}", row.class);
                    let details = serde_json::json!({
                        "class_name": row.class,
                        "property_count": row.properties.len()
                    });
                    merged_events.push(TimelineMergedEvent {
                        id: format!("wmi-instance-{}", idx),
                        source: "wmi-persistence".to_string(),
                        timestamp_utc: "unknown".to_string(),
                        timestamp_unix: 0,
                        event_type: "wmi-class-instance".to_string(),
                        event_category: Some("wmi".to_string()),
                        summary,
                        severity: "info".to_string(),
                        case_id: case_id.clone(),
                        evidence_id: None,
                        artifact_id: None,
                        actor: None,
                        table_name: None,
                        operation: None,
                        reason: None,
                        source_module: Some("wmi-persistence-activity".to_string()),
                        source_record_id: None,
                        data_json: serde_json::to_string(&details).ok(),
                    });
                }
            }
        } else if wmi_instances_explicit || source_requires_wmi {
            warnings.push(format!(
                "WMI instances input not found: {}",
                wmi_instances_path.display()
            ));
        }

        if source_requires_wmi && source_rows == 0 {
            warnings
                .push("No WMI persistence/activity rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "WMI persistence/activity rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_ntfs_mft() {
        let source_requires_ntfs_mft = matches!(source_filter, TimelineSourceFilter::NtfsMft);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if mft_input_path.exists() {
            let rows = forensic_engine::classification::mftparse::parse_mft_records_from_path(
                &mft_input_path,
                scan_cap,
            );
            source_rows = source_rows.saturating_add(rows.len());
            let paths = forensic_engine::classification::mftparse::reconstruct_mft_paths(&rows)
                .into_iter()
                .map(|v| (v.record_number, v.path))
                .collect::<std::collections::BTreeMap<u64, String>>();
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row
                    .modified_time
                    .or(row.created_time)
                    .or(row.mft_modified_time)
                    .or(row.accessed_time);
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }
                let full_path = paths
                    .get(&row.record_number)
                    .cloned()
                    .filter(|v| !v.trim().is_empty());
                let path_hint = full_path
                    .clone()
                    .or_else(|| row.file_name.clone())
                    .unwrap_or_else(|| format!("record_{}", row.record_number));
                let summary = format!("MFT record {}: {}", row.record_number, path_hint);
                let details = serde_json::json!({
                    "record_number": row.record_number,
                    "sequence_number": row.sequence_number,
                    "full_path": full_path,
                    "file_name": row.file_name,
                    "deleted": row.deleted,
                    "in_use": row.in_use,
                    "is_directory": row.is_directory
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("ntfs-mft-{}-{}", row.record_number, idx),
                    source: "ntfs-mft".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: "mft-record".to_string(),
                    event_category: Some("filesystem".to_string()),
                    summary,
                    severity: if row.deleted {
                        "warn".to_string()
                    } else {
                        "info".to_string()
                    },
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: None,
                    source_module: Some("ntfs-mft-fidelity".to_string()),
                    source_record_id: Some(row.record_number.to_string()),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if mft_input_explicit || source_requires_ntfs_mft {
            warnings.push(format!("MFT input not found: {}", mft_input_path.display()));
        }

        if source_requires_ntfs_mft && source_rows == 0 {
            warnings.push("No NTFS MFT rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "NTFS MFT rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_usn_journal() {
        let source_requires_usn = matches!(source_filter, TimelineSourceFilter::UsnJournal);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if usn_input_path.exists() {
            let rows = forensic_engine::classification::usnjrnl::parse_usnjrnl_records_from_path(
                &usn_input_path,
            );
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row.timestamp_unix;
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }
                let path_hint = row
                    .file_path
                    .clone()
                    .or_else(|| row.file_name.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                let event_type = row
                    .reason_flags
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "usn-change".to_string())
                    .to_ascii_lowercase();
                let summary = format!("USN change: {}", path_hint);
                let reason_text = if row.reason_flags.is_empty() {
                    None
                } else {
                    Some(row.reason_flags.join("|"))
                };
                let details = serde_json::json!({
                    "usn": row.usn,
                    "file_reference": row.file_reference,
                    "parent_reference": row.parent_reference,
                    "file_name": row.file_name,
                    "file_path": row.file_path,
                    "reason_raw": row.reason_raw,
                    "reason_flags": row.reason_flags
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("usn-journal-{}-{}", row.usn.unwrap_or_default(), idx),
                    source: "usn-journal".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type,
                    event_category: Some("filesystem".to_string()),
                    summary,
                    severity: if reason_text
                        .as_deref()
                        .map(|v| v.contains("FILE_DELETE"))
                        .unwrap_or(false)
                    {
                        "warn".to_string()
                    } else {
                        "info".to_string()
                    },
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: None,
                    reason: reason_text,
                    source_module: Some("usn-journal-fidelity".to_string()),
                    source_record_id: row.usn.map(|v| v.to_string()),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if usn_input_explicit || source_requires_usn {
            warnings.push(format!("USN input not found: {}", usn_input_path.display()));
        }

        if source_requires_usn && source_rows == 0 {
            warnings.push("No USN journal rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "USN journal rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_ntfs_logfile() {
        let source_requires_logfile = matches!(source_filter, TimelineSourceFilter::NtfsLogFile);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if logfile_input_path.exists() {
            let rows =
                forensic_engine::classification::logfile::parse_ntfs_logfile_signals_from_path(
                    &logfile_input_path,
                    scan_cap,
                );
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row.timestamp_unix.or_else(|| {
                    row.timestamp_utc
                        .as_deref()
                        .and_then(parse_utc_to_unix_seconds)
                });
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }
                let summary = if row.context.trim().is_empty() {
                    format!("NTFS LogFile signal: {}", row.signal)
                } else {
                    format!("NTFS LogFile signal: {} ({})", row.signal, row.context)
                };
                let details = serde_json::json!({
                    "offset": row.offset,
                    "signal": row.signal,
                    "context": row.context,
                    "sid": row.sid,
                    "user": row.user,
                    "device": row.device,
                    "process_path": row.process_path,
                    "source_module": row.source_module
                });
                let signal = details["signal"]
                    .as_str()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                merged_events.push(TimelineMergedEvent {
                    id: format!("ntfs-logfile-{}-{}", row.offset, idx),
                    source: "ntfs-logfile".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .or(row.timestamp_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: signal.replace('_', "-"),
                    event_category: Some("filesystem".to_string()),
                    summary,
                    severity: if signal.contains("delete")
                        || signal.contains("truncate")
                        || signal.contains("rename")
                    {
                        "warn".to_string()
                    } else {
                        "info".to_string()
                    },
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: details["user"].as_str().map(ToString::to_string),
                    table_name: None,
                    operation: None,
                    reason: details["signal"].as_str().map(ToString::to_string),
                    source_module: details["source_module"]
                        .as_str()
                        .map(ToString::to_string)
                        .or_else(|| Some("ntfs-logfile-signals".to_string())),
                    source_record_id: Some(row.offset.to_string()),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if logfile_input_explicit || source_requires_logfile {
            warnings.push(format!(
                "NTFS LogFile input not found: {}",
                logfile_input_path.display()
            ));
        }

        if source_requires_logfile && source_rows == 0 {
            warnings.push("No NTFS LogFile rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "NTFS LogFile rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_recycle_bin() {
        let source_requires_recycle = matches!(source_filter, TimelineSourceFilter::RecycleBin);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if recycle_input_path.exists() {
            let rows = forensic_engine::classification::recyclebin::parse_recycle_entries_from_path(
                &recycle_input_path,
                scan_cap,
            );
            source_rows = source_rows.saturating_add(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let ts = row.deleted_time;
                if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                    continue;
                }
                if let Some(to_ts) = to_unix {
                    if let Some(v) = ts {
                        if v > to_ts {
                            continue;
                        }
                    }
                }
                if let Some(from_ts) = from_unix {
                    if let Some(v) = ts {
                        if v < from_ts {
                            continue;
                        }
                    }
                }
                if ts.is_some() {
                    with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                }
                let path_hint = row
                    .original_path
                    .clone()
                    .unwrap_or_else(|| row.file_name.clone());
                let summary = format!("Recycle Bin deletion: {}", path_hint);
                let details = serde_json::json!({
                    "file_name": row.file_name,
                    "original_path": row.original_path,
                    "deleted_time": row.deleted_time,
                    "file_size": row.file_size,
                    "drive_letter": row.drive_letter.to_string(),
                    "owner_sid": row.owner_sid
                });
                merged_events.push(TimelineMergedEvent {
                    id: format!("recycle-bin-{}-{}", row.drive_letter, idx),
                    source: "recycle-bin".to_string(),
                    timestamp_utc: ts
                        .map(unix_seconds_to_utc)
                        .unwrap_or_else(|| "unknown".to_string()),
                    timestamp_unix: ts.unwrap_or(0),
                    event_type: "recycle-delete".to_string(),
                    event_category: Some("deletion".to_string()),
                    summary,
                    severity: "warn".to_string(),
                    case_id: case_id.clone(),
                    evidence_id: None,
                    artifact_id: None,
                    actor: None,
                    table_name: None,
                    operation: Some("delete".to_string()),
                    reason: details["owner_sid"].as_str().map(ToString::to_string),
                    source_module: Some("recycle-bin-artifacts".to_string()),
                    source_record_id: details["file_name"].as_str().map(ToString::to_string),
                    data_json: serde_json::to_string(&details).ok(),
                });
            }
        } else if recycle_input_explicit || source_requires_recycle {
            warnings.push(format!(
                "Recycle Bin input not found: {}",
                recycle_input_path.display()
            ));
        }

        if source_requires_recycle && source_rows == 0 {
            warnings.push("No Recycle Bin rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "Recycle Bin rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    if source_filter.includes_defender_artifacts() {
        let source_requires_defender =
            matches!(source_filter, TimelineSourceFilter::DefenderArtifacts);
        let mut source_rows = 0usize;
        let mut with_timestamp_rows = 0usize;

        if defender_input_path.exists() {
            match load_defender_artifacts_payload(&defender_input_path) {
                Ok((payload, envelope_note)) => {
                    if let Some(note) = envelope_note {
                        warnings.push(note);
                    }

                    if let Some(status) = payload.get("status").and_then(|v| v.as_object()) {
                        source_rows = source_rows.saturating_add(1);
                        let ts = status
                            .get("last_scan_unix")
                            .and_then(json_value_to_unix_seconds)
                            .or_else(|| {
                                status
                                    .get("last_scan_utc")
                                    .and_then(json_value_to_unix_seconds)
                            });
                        let within_range =
                            if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                                false
                            } else {
                                let not_after_to =
                                    to_unix.is_none_or(|to_ts| ts.is_none_or(|v| v <= to_ts));
                                let not_before_from =
                                    from_unix.is_none_or(|from_ts| ts.is_none_or(|v| v >= from_ts));
                                not_after_to && not_before_from
                            };
                        if within_range {
                            if ts.is_some() {
                                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                            }
                            let details = serde_json::Value::Object(status.clone());
                            let enabled = status
                                .get("enabled")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let rtp = status
                                .get("real_time_protection")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            merged_events.push(TimelineMergedEvent {
                                id: format!("defender-status-{}", ts.unwrap_or(0)),
                                source: "defender-artifacts".to_string(),
                                timestamp_utc: ts
                                    .map(unix_seconds_to_utc)
                                    .unwrap_or_else(|| "unknown".to_string()),
                                timestamp_unix: ts.unwrap_or(0),
                                event_type: "defender-status".to_string(),
                                event_category: Some("status".to_string()),
                                summary: format!(
                                    "Defender status snapshot (enabled={}, realtime={})",
                                    enabled, rtp
                                ),
                                severity: "info".to_string(),
                                case_id: case_id.clone(),
                                evidence_id: None,
                                artifact_id: None,
                                actor: None,
                                table_name: None,
                                operation: None,
                                reason: None,
                                source_module: Some("defender-artifacts".to_string()),
                                source_record_id: None,
                                data_json: serde_json::to_string(&details).ok(),
                            });
                        }
                    }

                    if let Some(rows) = payload.get("quarantine_items").and_then(|v| v.as_array()) {
                        source_rows = source_rows.saturating_add(rows.len());
                        for (idx, row) in rows.iter().enumerate() {
                            let ts = json_field_unix_seconds(
                                row,
                                "quarantine_time_unix",
                                "quarantine_time_utc",
                            );
                            if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                                continue;
                            }
                            if let Some(to_ts) = to_unix {
                                if let Some(v) = ts {
                                    if v > to_ts {
                                        continue;
                                    }
                                }
                            }
                            if let Some(from_ts) = from_unix {
                                if let Some(v) = ts {
                                    if v < from_ts {
                                        continue;
                                    }
                                }
                            }
                            if ts.is_some() {
                                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                            }

                            let threat = row
                                .get("threat_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown-threat");
                            let file_path = row
                                .get("file_path")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown-path");
                            merged_events.push(TimelineMergedEvent {
                                id: format!("defender-quarantine-{}-{}", idx, ts.unwrap_or(0)),
                                source: "defender-artifacts".to_string(),
                                timestamp_utc: ts
                                    .map(unix_seconds_to_utc)
                                    .unwrap_or_else(|| "unknown".to_string()),
                                timestamp_unix: ts.unwrap_or(0),
                                event_type: "defender-quarantine".to_string(),
                                event_category: Some("quarantine".to_string()),
                                summary: format!("Defender quarantined {} ({})", file_path, threat),
                                severity: "warn".to_string(),
                                case_id: case_id.clone(),
                                evidence_id: None,
                                artifact_id: None,
                                actor: None,
                                table_name: None,
                                operation: Some("quarantine".to_string()),
                                reason: Some(threat.to_string()),
                                source_module: Some("defender-artifacts".to_string()),
                                source_record_id: row
                                    .get("file_path")
                                    .and_then(|v| v.as_str())
                                    .map(ToString::to_string),
                                data_json: serde_json::to_string(row).ok(),
                            });
                        }
                    }

                    if let Some(rows) = payload.get("scan_history").and_then(|v| v.as_array()) {
                        source_rows = source_rows.saturating_add(rows.len());
                        for (idx, row) in rows.iter().enumerate() {
                            let ts = json_field_unix_seconds(row, "end_time_unix", "end_time_utc")
                                .or_else(|| {
                                    json_field_unix_seconds(
                                        row,
                                        "start_time_unix",
                                        "start_time_utc",
                                    )
                                });
                            if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                                continue;
                            }
                            if let Some(to_ts) = to_unix {
                                if let Some(v) = ts {
                                    if v > to_ts {
                                        continue;
                                    }
                                }
                            }
                            if let Some(from_ts) = from_unix {
                                if let Some(v) = ts {
                                    if v < from_ts {
                                        continue;
                                    }
                                }
                            }
                            if ts.is_some() {
                                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                            }
                            let scan_type = row
                                .get("scan_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let scan_result = row
                                .get("scan_result")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let severity = if scan_result.eq_ignore_ascii_case("failed")
                                || scan_result.eq_ignore_ascii_case("cancelled")
                            {
                                "warn".to_string()
                            } else {
                                "info".to_string()
                            };
                            merged_events.push(TimelineMergedEvent {
                                id: format!("defender-scan-{}-{}", idx, ts.unwrap_or(0)),
                                source: "defender-artifacts".to_string(),
                                timestamp_utc: ts
                                    .map(unix_seconds_to_utc)
                                    .unwrap_or_else(|| "unknown".to_string()),
                                timestamp_unix: ts.unwrap_or(0),
                                event_type: "defender-scan".to_string(),
                                event_category: Some("scan".to_string()),
                                summary: format!("Defender {} scan {}", scan_type, scan_result),
                                severity,
                                case_id: case_id.clone(),
                                evidence_id: None,
                                artifact_id: None,
                                actor: None,
                                table_name: None,
                                operation: Some("scan".to_string()),
                                reason: Some(scan_result.to_string()),
                                source_module: Some("defender-artifacts".to_string()),
                                source_record_id: None,
                                data_json: serde_json::to_string(row).ok(),
                            });
                        }
                    }

                    if let Some(rows) = payload
                        .get("endpoint")
                        .and_then(|v| v.get("alerts"))
                        .and_then(|v| v.as_array())
                    {
                        source_rows = source_rows.saturating_add(rows.len());
                        for (idx, row) in rows.iter().enumerate() {
                            let ts = json_field_unix_seconds(row, "detected_unix", "detected_utc");
                            if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                                continue;
                            }
                            if let Some(to_ts) = to_unix {
                                if let Some(v) = ts {
                                    if v > to_ts {
                                        continue;
                                    }
                                }
                            }
                            if let Some(from_ts) = from_unix {
                                if let Some(v) = ts {
                                    if v < from_ts {
                                        continue;
                                    }
                                }
                            }
                            if ts.is_some() {
                                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                            }
                            let title = row
                                .get("title")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Defender endpoint alert");
                            let severity_label = row
                                .get("severity")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            merged_events.push(TimelineMergedEvent {
                                id: format!("defender-alert-{}-{}", idx, ts.unwrap_or(0)),
                                source: "defender-artifacts".to_string(),
                                timestamp_utc: ts
                                    .map(unix_seconds_to_utc)
                                    .unwrap_or_else(|| "unknown".to_string()),
                                timestamp_unix: ts.unwrap_or(0),
                                event_type: "defender-endpoint-alert".to_string(),
                                event_category: Some("endpoint-alert".to_string()),
                                summary: title.to_string(),
                                severity: if severity_label.eq_ignore_ascii_case("high")
                                    || severity_label.eq_ignore_ascii_case("critical")
                                {
                                    "warn".to_string()
                                } else {
                                    "info".to_string()
                                },
                                case_id: case_id.clone(),
                                evidence_id: None,
                                artifact_id: None,
                                actor: row
                                    .get("machine_name")
                                    .and_then(|v| v.as_str())
                                    .map(ToString::to_string),
                                table_name: None,
                                operation: None,
                                reason: row
                                    .get("category")
                                    .and_then(|v| v.as_str())
                                    .map(ToString::to_string),
                                source_module: Some("defender-endpoint-alerts".to_string()),
                                source_record_id: row
                                    .get("alert_id")
                                    .and_then(|v| v.as_str())
                                    .map(ToString::to_string),
                                data_json: serde_json::to_string(row).ok(),
                            });
                        }
                    }

                    if let Some(rows) = payload
                        .get("endpoint")
                        .and_then(|v| v.get("indicators"))
                        .and_then(|v| v.as_array())
                    {
                        source_rows = source_rows.saturating_add(rows.len());
                        for (idx, row) in rows.iter().enumerate() {
                            let ts = json_field_unix_seconds(row, "created_unix", "created_utc");
                            if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                                continue;
                            }
                            if let Some(to_ts) = to_unix {
                                if let Some(v) = ts {
                                    if v > to_ts {
                                        continue;
                                    }
                                }
                            }
                            if let Some(from_ts) = from_unix {
                                if let Some(v) = ts {
                                    if v < from_ts {
                                        continue;
                                    }
                                }
                            }
                            if ts.is_some() {
                                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                            }
                            let value = row
                                .get("value")
                                .and_then(|v| v.as_str())
                                .unwrap_or("indicator");
                            let indicator_type = row
                                .get("indicator_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            merged_events.push(TimelineMergedEvent {
                                id: format!("defender-indicator-{}-{}", idx, ts.unwrap_or(0)),
                                source: "defender-artifacts".to_string(),
                                timestamp_utc: ts
                                    .map(unix_seconds_to_utc)
                                    .unwrap_or_else(|| "unknown".to_string()),
                                timestamp_unix: ts.unwrap_or(0),
                                event_type: "defender-indicator".to_string(),
                                event_category: Some("endpoint-indicator".to_string()),
                                summary: format!(
                                    "Defender indicator [{}] {}",
                                    indicator_type, value
                                ),
                                severity: "info".to_string(),
                                case_id: case_id.clone(),
                                evidence_id: None,
                                artifact_id: None,
                                actor: None,
                                table_name: None,
                                operation: row
                                    .get("action")
                                    .and_then(|v| v.as_str())
                                    .map(ToString::to_string),
                                reason: None,
                                source_module: Some("defender-endpoint-indicators".to_string()),
                                source_record_id: None,
                                data_json: serde_json::to_string(row).ok(),
                            });
                        }
                    }

                    if let Some(rows) = payload
                        .get("endpoint")
                        .and_then(|v| v.get("file_profiles"))
                        .and_then(|v| v.as_array())
                    {
                        source_rows = source_rows.saturating_add(rows.len());
                        for (idx, row) in rows.iter().enumerate() {
                            let ts =
                                json_field_unix_seconds(row, "first_seen_unix", "first_seen_utc");
                            if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                                continue;
                            }
                            if let Some(to_ts) = to_unix {
                                if let Some(v) = ts {
                                    if v > to_ts {
                                        continue;
                                    }
                                }
                            }
                            if let Some(from_ts) = from_unix {
                                if let Some(v) = ts {
                                    if v < from_ts {
                                        continue;
                                    }
                                }
                            }
                            if ts.is_some() {
                                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                            }
                            let detection_name = row
                                .get("detection_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let sha1 = row.get("sha1").and_then(|v| v.as_str()).unwrap_or("n/a");
                            let is_malicious = row
                                .get("is_malicious")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            merged_events.push(TimelineMergedEvent {
                                id: format!("defender-file-profile-{}-{}", idx, ts.unwrap_or(0)),
                                source: "defender-artifacts".to_string(),
                                timestamp_utc: ts
                                    .map(unix_seconds_to_utc)
                                    .unwrap_or_else(|| "unknown".to_string()),
                                timestamp_unix: ts.unwrap_or(0),
                                event_type: "defender-file-profile".to_string(),
                                event_category: Some("endpoint-file-profile".to_string()),
                                summary: format!(
                                    "Defender file profile {} ({})",
                                    detection_name, sha1
                                ),
                                severity: if is_malicious {
                                    "warn".to_string()
                                } else {
                                    "info".to_string()
                                },
                                case_id: case_id.clone(),
                                evidence_id: None,
                                artifact_id: None,
                                actor: None,
                                table_name: None,
                                operation: None,
                                reason: None,
                                source_module: Some("defender-endpoint-file-profiles".to_string()),
                                source_record_id: row
                                    .get("sha1")
                                    .and_then(|v| v.as_str())
                                    .map(ToString::to_string),
                                data_json: serde_json::to_string(row).ok(),
                            });
                        }
                    }

                    if let Some(rows) = payload
                        .get("endpoint")
                        .and_then(|v| v.get("machine_actions"))
                        .and_then(|v| v.as_array())
                    {
                        source_rows = source_rows.saturating_add(rows.len());
                        for (idx, row) in rows.iter().enumerate() {
                            let ts =
                                json_field_unix_seconds(row, "requested_unix", "requested_utc")
                                    .or_else(|| {
                                        json_field_unix_seconds(
                                            row,
                                            "completed_unix",
                                            "completed_utc",
                                        )
                                    });
                            if ts.is_none() && (from_unix.is_some() || to_unix.is_some()) {
                                continue;
                            }
                            if let Some(to_ts) = to_unix {
                                if let Some(v) = ts {
                                    if v > to_ts {
                                        continue;
                                    }
                                }
                            }
                            if let Some(from_ts) = from_unix {
                                if let Some(v) = ts {
                                    if v < from_ts {
                                        continue;
                                    }
                                }
                            }
                            if ts.is_some() {
                                with_timestamp_rows = with_timestamp_rows.saturating_add(1);
                            }
                            let action_type = row
                                .get("action_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let status = row
                                .get("status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            merged_events.push(TimelineMergedEvent {
                                id: format!("defender-machine-action-{}-{}", idx, ts.unwrap_or(0)),
                                source: "defender-artifacts".to_string(),
                                timestamp_utc: ts
                                    .map(unix_seconds_to_utc)
                                    .unwrap_or_else(|| "unknown".to_string()),
                                timestamp_unix: ts.unwrap_or(0),
                                event_type: "defender-machine-action".to_string(),
                                event_category: Some("endpoint-machine-action".to_string()),
                                summary: format!(
                                    "Defender machine action {} ({})",
                                    action_type, status
                                ),
                                severity: "info".to_string(),
                                case_id: case_id.clone(),
                                evidence_id: None,
                                artifact_id: None,
                                actor: row
                                    .get("machine_id")
                                    .and_then(|v| v.as_str())
                                    .map(ToString::to_string),
                                table_name: None,
                                operation: Some(action_type.to_string()),
                                reason: Some(status.to_string()),
                                source_module: Some(
                                    "defender-endpoint-machine-actions".to_string(),
                                ),
                                source_record_id: row
                                    .get("action_id")
                                    .and_then(|v| v.as_str())
                                    .map(ToString::to_string),
                                data_json: serde_json::to_string(row).ok(),
                            });
                        }
                    }
                }
                Err(e) => warnings.push(format!(
                    "Could not parse Defender artifacts input {}: {}",
                    defender_input_path.display(),
                    e
                )),
            }
        } else if defender_input_explicit || source_requires_defender {
            warnings.push(format!(
                "Defender artifacts input not found: {}",
                defender_input_path.display()
            ));
        }

        if source_requires_defender && source_rows == 0 {
            warnings.push("No Defender artifacts rows found from configured inputs.".to_string());
        } else if source_rows > 0 && with_timestamp_rows == 0 {
            warnings.push(
                "Defender artifacts rows were parsed, but no timestamped rows were available for timeline."
                    .to_string(),
            );
        }
    }

    merged_events.sort_by(|a, b| {
        b.timestamp_unix
            .cmp(&a.timestamp_unix)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.event_type.cmp(&b.event_type))
            .then_with(|| a.id.cmp(&b.id))
    });
    merged_events = dedupe_timeline_events(merged_events);

    let mut prefilter_rows_by_source: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut prefilter_timestamped_by_source: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for event in &merged_events {
        *prefilter_rows_by_source
            .entry(event.source.clone())
            .or_insert(0) += 1;
        if event.timestamp_unix > 0 {
            *prefilter_timestamped_by_source
                .entry(event.source.clone())
                .or_insert(0) += 1;
        }
    }

    let total_prefilter = merged_events.len();
    if severity_filter.is_some() || event_type_filter.is_some() || contains_filter.is_some() {
        merged_events = merged_events
            .into_iter()
            .filter(|event| {
                let severity_ok = severity_filter
                    .as_deref()
                    .is_none_or(|needle| event.severity.eq_ignore_ascii_case(needle));
                let event_type_ok = event_type_filter
                    .as_deref()
                    .is_none_or(|needle| event.event_type.to_ascii_lowercase().contains(needle));
                let contains_ok = contains_filter.as_deref().is_none_or(|needle| {
                    event.summary.to_ascii_lowercase().contains(needle)
                        || event
                            .reason
                            .as_deref()
                            .map(|v| v.to_ascii_lowercase().contains(needle))
                            .unwrap_or(false)
                        || event
                            .data_json
                            .as_deref()
                            .map(|v| v.to_ascii_lowercase().contains(needle))
                            .unwrap_or(false)
                });
                severity_ok && event_type_ok && contains_ok
            })
            .collect::<Vec<_>>();
    }
    let total_after_filters = merged_events.len();
    let dropped_by_filters = total_prefilter.saturating_sub(total_after_filters);
    let mut filtered_rows_by_source: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut filtered_timestamped_by_source: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for event in &merged_events {
        *filtered_rows_by_source
            .entry(event.source.clone())
            .or_insert(0) += 1;
        if event.timestamp_unix > 0 {
            *filtered_timestamped_by_source
                .entry(event.source.clone())
                .or_insert(0) += 1;
        }
    }
    let total_available = merged_events.len();
    let start_index = std::cmp::min(cursor_offset, total_available);
    let next_index = start_index.saturating_add(limit);
    let next_cursor = if next_index < total_available {
        Some(next_index.to_string())
    } else {
        None
    };
    let merged_events = merged_events
        .into_iter()
        .skip(start_index)
        .take(limit)
        .collect::<Vec<_>>();

    let mut returned_rows_by_source: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut returned_timestamped_by_source: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for event in &merged_events {
        *returned_rows_by_source
            .entry(event.source.clone())
            .or_insert(0) += 1;
        if event.timestamp_unix > 0 {
            *returned_timestamped_by_source
                .entry(event.source.clone())
                .or_insert(0) += 1;
        }
    }

    let mut activity_count = 0usize;
    let mut evidence_count = 0usize;
    let mut violations_count = 0usize;
    let mut execution_count = 0usize;
    let mut prefetch_count = 0usize;
    let mut jumplist_count = 0usize;
    let mut lnk_shortcuts_count = 0usize;
    let mut browser_forensics_count = 0usize;
    let mut rdp_remote_access_count = 0usize;
    let mut usb_device_history_count = 0usize;
    let mut restore_shadow_copies_count = 0usize;
    let mut user_activity_mru_count = 0usize;
    let mut timeline_correlation_qa_count = 0usize;
    let mut srum_count = 0usize;
    let mut evtx_security_count = 0usize;
    let mut evtx_sysmon_count = 0usize;
    let mut powershell_count = 0usize;
    let mut registry_user_hives_count = 0usize;
    let mut registry_persistence_count = 0usize;
    let mut shimcache_count = 0usize;
    let mut amcache_count = 0usize;
    let mut bam_dam_count = 0usize;
    let mut services_drivers_count = 0usize;
    let mut scheduled_tasks_count = 0usize;
    let mut wmi_persistence_count = 0usize;
    let mut ntfs_mft_count = 0usize;
    let mut usn_journal_count = 0usize;
    let mut ntfs_logfile_count = 0usize;
    let mut recycle_bin_count = 0usize;
    let mut defender_artifacts_count = 0usize;
    for event in &merged_events {
        match event.source.as_str() {
            "activity" => activity_count += 1,
            "evidence" => evidence_count += 1,
            "violations" => violations_count += 1,
            "execution" => execution_count += 1,
            "prefetch" => prefetch_count += 1,
            "jumplist" => jumplist_count += 1,
            "lnk-shortcuts" => lnk_shortcuts_count += 1,
            "browser-forensics" => browser_forensics_count += 1,
            "rdp-remote-access" => rdp_remote_access_count += 1,
            "usb-device-history" => usb_device_history_count += 1,
            "restore-shadow-copies" => restore_shadow_copies_count += 1,
            "user-activity-mru" => user_activity_mru_count += 1,
            "timeline-correlation-qa" => timeline_correlation_qa_count += 1,
            "srum" => srum_count += 1,
            "evtx-security" => evtx_security_count += 1,
            "evtx-sysmon" => evtx_sysmon_count += 1,
            "powershell" => powershell_count += 1,
            "registry-user-hives" => registry_user_hives_count += 1,
            "registry-persistence" => registry_persistence_count += 1,
            "shimcache" => shimcache_count += 1,
            "amcache" => amcache_count += 1,
            "bam-dam" => bam_dam_count += 1,
            "services-drivers" => services_drivers_count += 1,
            "scheduled-tasks" => scheduled_tasks_count += 1,
            "wmi-persistence" => wmi_persistence_count += 1,
            "ntfs-mft" => ntfs_mft_count += 1,
            "usn-journal" => usn_journal_count += 1,
            "ntfs-logfile" => ntfs_logfile_count += 1,
            "recycle-bin" => recycle_bin_count += 1,
            "defender-artifacts" => defender_artifacts_count += 1,
            _ => {}
        }
    }

    let mut timeline_inputs = serde_json::Map::new();
    timeline_inputs.insert("severity".to_string(), serde_json::json!(severity_filter));
    timeline_inputs.insert(
        "event_type".to_string(),
        serde_json::json!(event_type_filter),
    );
    timeline_inputs.insert("contains".to_string(), serde_json::json!(contains_filter));
    timeline_inputs.insert(
        "prefetch_dir".to_string(),
        serde_json::json!(prefetch_dir.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "prefetch_found".to_string(),
        serde_json::json!(prefetch_dir.exists()),
    );
    timeline_inputs.insert(
        "jumplist_path".to_string(),
        serde_json::json!(jumplist_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "jumplist_found".to_string(),
        serde_json::json!(jumplist_path.exists()),
    );
    timeline_inputs.insert(
        "lnk_input".to_string(),
        serde_json::json!(lnk_input_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "lnk_found".to_string(),
        serde_json::json!(lnk_input_path.exists()),
    );
    timeline_inputs.insert(
        "browser_input".to_string(),
        serde_json::json!(browser_input_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "browser_found".to_string(),
        serde_json::json!(browser_input_path.exists()),
    );
    timeline_inputs.insert(
        "rdp_input".to_string(),
        serde_json::json!(rdp_input_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "rdp_found".to_string(),
        serde_json::json!(rdp_input_path.exists()),
    );
    timeline_inputs.insert(
        "usb_input".to_string(),
        serde_json::json!(usb_input_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "usb_found".to_string(),
        serde_json::json!(usb_input_path.exists()),
    );
    timeline_inputs.insert(
        "restore_shadow_input".to_string(),
        serde_json::json!(restore_shadow_input_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "restore_shadow_found".to_string(),
        serde_json::json!(restore_shadow_input_path.exists()),
    );
    timeline_inputs.insert(
        "user_activity_input".to_string(),
        serde_json::json!(user_activity_input_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "user_activity_found".to_string(),
        serde_json::json!(user_activity_input_path.exists()),
    );
    timeline_inputs.insert(
        "timeline_correlation_input".to_string(),
        serde_json::json!(timeline_correlation_input_path
            .to_string_lossy()
            .to_string()),
    );
    timeline_inputs.insert(
        "timeline_correlation_found".to_string(),
        serde_json::json!(timeline_correlation_input_path.exists()),
    );
    timeline_inputs.insert(
        "srum_input".to_string(),
        serde_json::json!(srum_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "srum_found".to_string(),
        serde_json::json!(srum_path.exists()),
    );
    timeline_inputs.insert(
        "evtx_security_input".to_string(),
        serde_json::json!(evtx_security_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "evtx_security_found".to_string(),
        serde_json::json!(evtx_security_path.exists()),
    );
    timeline_inputs.insert(
        "evtx_sysmon_input".to_string(),
        serde_json::json!(evtx_sysmon_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "evtx_sysmon_found".to_string(),
        serde_json::json!(evtx_sysmon_path.exists()),
    );
    timeline_inputs.insert(
        "powershell_history".to_string(),
        serde_json::json!(powershell_history_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "powershell_history_found".to_string(),
        serde_json::json!(powershell_history_path.exists()),
    );
    timeline_inputs.insert(
        "powershell_script_log".to_string(),
        serde_json::json!(powershell_script_log_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "powershell_script_log_found".to_string(),
        serde_json::json!(powershell_script_log_path.exists()),
    );
    timeline_inputs.insert(
        "powershell_events".to_string(),
        serde_json::json!(powershell_events_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "powershell_events_found".to_string(),
        serde_json::json!(powershell_events_path.exists()),
    );
    timeline_inputs.insert(
        "defender_input".to_string(),
        serde_json::json!(defender_input_path.to_string_lossy().to_string()),
    );
    timeline_inputs.insert(
        "defender_found".to_string(),
        serde_json::json!(defender_input_path.exists()),
    );

    let mut quality_rows_by_source = serde_json::Map::new();
    let mut source_keys = std::collections::BTreeSet::new();
    source_keys.extend(prefilter_rows_by_source.keys().cloned());
    source_keys.extend(filtered_rows_by_source.keys().cloned());
    source_keys.extend(returned_rows_by_source.keys().cloned());
    for source in source_keys {
        let rows_scanned = prefilter_rows_by_source.get(&source).copied().unwrap_or(0);
        let rows_timestamped = prefilter_timestamped_by_source
            .get(&source)
            .copied()
            .unwrap_or(0);
        let rows_after_filters = filtered_rows_by_source.get(&source).copied().unwrap_or(0);
        let rows_returned = returned_rows_by_source.get(&source).copied().unwrap_or(0);
        let rows_dropped = rows_scanned.saturating_sub(rows_after_filters);
        let rows_returned_timestamped = returned_timestamped_by_source
            .get(&source)
            .copied()
            .unwrap_or(0);
        quality_rows_by_source.insert(
            source,
            serde_json::json!({
                "rows_scanned": rows_scanned,
                "rows_timestamped": rows_timestamped,
                "rows_dropped": rows_dropped,
                "rows_after_filters": rows_after_filters,
                "rows_returned": rows_returned,
                "rows_returned_timestamped": rows_returned_timestamped
            }),
        );
    }

    let mut counts_by_source = serde_json::Map::new();
    counts_by_source.insert("activity".to_string(), serde_json::json!(activity_count));
    counts_by_source.insert("evidence".to_string(), serde_json::json!(evidence_count));
    counts_by_source.insert(
        "violations".to_string(),
        serde_json::json!(violations_count),
    );
    counts_by_source.insert("execution".to_string(), serde_json::json!(execution_count));
    counts_by_source.insert("prefetch".to_string(), serde_json::json!(prefetch_count));
    counts_by_source.insert("jumplist".to_string(), serde_json::json!(jumplist_count));
    counts_by_source.insert(
        "lnk_shortcuts".to_string(),
        serde_json::json!(lnk_shortcuts_count),
    );
    counts_by_source.insert(
        "browser_forensics".to_string(),
        serde_json::json!(browser_forensics_count),
    );
    counts_by_source.insert(
        "rdp_remote_access".to_string(),
        serde_json::json!(rdp_remote_access_count),
    );
    counts_by_source.insert(
        "usb_device_history".to_string(),
        serde_json::json!(usb_device_history_count),
    );
    counts_by_source.insert(
        "restore_shadow_copies".to_string(),
        serde_json::json!(restore_shadow_copies_count),
    );
    counts_by_source.insert(
        "user_activity_mru".to_string(),
        serde_json::json!(user_activity_mru_count),
    );
    counts_by_source.insert(
        "timeline_correlation_qa".to_string(),
        serde_json::json!(timeline_correlation_qa_count),
    );
    counts_by_source.insert("srum".to_string(), serde_json::json!(srum_count));
    counts_by_source.insert(
        "evtx_security".to_string(),
        serde_json::json!(evtx_security_count),
    );
    counts_by_source.insert(
        "evtx_sysmon".to_string(),
        serde_json::json!(evtx_sysmon_count),
    );
    counts_by_source.insert(
        "powershell".to_string(),
        serde_json::json!(powershell_count),
    );
    counts_by_source.insert(
        "registry_user_hives".to_string(),
        serde_json::json!(registry_user_hives_count),
    );
    counts_by_source.insert(
        "registry_persistence".to_string(),
        serde_json::json!(registry_persistence_count),
    );
    counts_by_source.insert("shimcache".to_string(), serde_json::json!(shimcache_count));
    counts_by_source.insert("amcache".to_string(), serde_json::json!(amcache_count));
    counts_by_source.insert("bam_dam".to_string(), serde_json::json!(bam_dam_count));
    counts_by_source.insert(
        "services_drivers".to_string(),
        serde_json::json!(services_drivers_count),
    );
    counts_by_source.insert(
        "scheduled_tasks".to_string(),
        serde_json::json!(scheduled_tasks_count),
    );
    counts_by_source.insert(
        "wmi_persistence".to_string(),
        serde_json::json!(wmi_persistence_count),
    );
    counts_by_source.insert("ntfs_mft".to_string(), serde_json::json!(ntfs_mft_count));
    counts_by_source.insert(
        "usn_journal".to_string(),
        serde_json::json!(usn_journal_count),
    );
    counts_by_source.insert(
        "ntfs_logfile".to_string(),
        serde_json::json!(ntfs_logfile_count),
    );
    counts_by_source.insert(
        "recycle_bin".to_string(),
        serde_json::json!(recycle_bin_count),
    );
    counts_by_source.insert(
        "defender_artifacts".to_string(),
        serde_json::json!(defender_artifacts_count),
    );

    let mut quality_totals = serde_json::Map::new();
    quality_totals.insert(
        "rows_prefilter".to_string(),
        serde_json::json!(total_prefilter),
    );
    quality_totals.insert(
        "rows_after_filters".to_string(),
        serde_json::json!(total_after_filters),
    );
    quality_totals.insert(
        "rows_dropped_by_filters".to_string(),
        serde_json::json!(dropped_by_filters),
    );
    quality_totals.insert(
        "rows_returned_page".to_string(),
        serde_json::json!(merged_events.len()),
    );

    let mut quality = serde_json::Map::new();
    quality.insert(
        "totals".to_string(),
        serde_json::Value::Object(quality_totals),
    );
    quality.insert(
        "rows_by_source".to_string(),
        serde_json::Value::Object(quality_rows_by_source),
    );

    let mut timeline_data_obj = serde_json::Map::new();
    timeline_data_obj.insert("case_id".to_string(), serde_json::json!(case_id));
    timeline_data_obj.insert(
        "db_path".to_string(),
        serde_json::json!(db_path.to_string_lossy().to_string()),
    );
    timeline_data_obj.insert("from_utc".to_string(), serde_json::json!(from_utc));
    timeline_data_obj.insert("to_utc".to_string(), serde_json::json!(to_utc));
    timeline_data_obj.insert("cursor".to_string(), serde_json::json!(cursor_raw));
    timeline_data_obj.insert("next_cursor".to_string(), serde_json::json!(next_cursor));
    timeline_data_obj.insert("limit".to_string(), serde_json::json!(limit));
    timeline_data_obj.insert(
        "source_filter".to_string(),
        serde_json::json!(source_filter.as_str()),
    );
    timeline_data_obj.insert(
        "total_available".to_string(),
        serde_json::json!(total_available),
    );
    timeline_data_obj.insert(
        "total_returned".to_string(),
        serde_json::json!(merged_events.len()),
    );
    timeline_data_obj.insert(
        "inputs".to_string(),
        serde_json::Value::Object(timeline_inputs),
    );
    timeline_data_obj.insert("quality".to_string(), serde_json::Value::Object(quality));
    timeline_data_obj.insert(
        "counts_by_source".to_string(),
        serde_json::Value::Object(counts_by_source),
    );
    timeline_data_obj.insert("events".to_string(), serde_json::json!(merged_events));
    let timeline_data = serde_json::Value::Object(timeline_data_obj);

    if json_output {
        if !quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(&timeline_data).unwrap_or_default()
            );
        }
    } else if !quiet {
        println!("=== Case Timeline ===");
        println!(
            "Case: {}",
            timeline_data["case_id"].as_str().unwrap_or_default()
        );
        println!("Source: {}", source_filter.as_str());
        println!(
            "Returned: {}",
            timeline_data["total_returned"].as_u64().unwrap_or(0)
        );
        if let Some(from) = timeline_data["from_utc"].as_str() {
            println!("From: {}", from);
        }
        if let Some(to) = timeline_data["to_utc"].as_str() {
            println!("To: {}", to);
        }
        println!();

        if let Some(events) = timeline_data["events"].as_array() {
            for event in events.iter().take(20) {
                let ts = event["timestamp_utc"].as_str().unwrap_or_default();
                let source = event["source"].as_str().unwrap_or_default();
                let event_type = event["event_type"].as_str().unwrap_or_default();
                let summary = event["summary"].as_str().unwrap_or_default();
                println!("[{}] {} {} - {}", ts, source, event_type, summary);
            }
            if events.len() > 20 {
                println!("... ({} more events)", events.len() - 20);
            }
        }
        if !warnings.is_empty() {
            println!();
            println!("Warning: {}", warnings.join("; "));
        }
    }

    if let Some(ref json_path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "timeline",
            original_args.clone(),
            EXIT_OK,
            start_time.elapsed().as_millis() as u64,
        )
        .with_data(timeline_data);

        if !warnings.is_empty() {
            envelope = envelope.warn(warnings.join("; "));
        }

        let _ = envelope.write_to_file(json_path);
    }

    std::process::exit(EXIT_OK);
}

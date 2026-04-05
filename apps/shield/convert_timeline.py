import re

path = r'd:\forensic-suite\cli\src\commands\timeline.rs'

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Generate the TimelineArgs struct
clap_struct = '''
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
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
'''

# We need to replace the execute signature and the setup block.
# The `execute` block starts at `pub fn execute(mut args: Vec<String>) {`
# and the argument parsing ends after the `match` loop around line 672.
# We will construct the new variable assignments based on `args` fields.

var_assignments = '''
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
    let prefetch_dir = args.prefetch_dir.or(env_prefetch_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("C:\\Windows\\Prefetch"));
    let prefetch_input_explicit = args.prefetch_dir.is_some() || env_prefetch_path.is_some();

    let env_jumplist_path = std::env::var("FORENSIC_JUMPLIST_PATH").ok();
    let jumplist_path = args.jumplist_path.or(env_jumplist_path.clone().map(PathBuf::from)).unwrap_or_else(crate::default_jumplist_path);
    let jumplist_input_explicit = args.jumplist_path.is_some() || env_jumplist_path.is_some();

    let env_shortcuts_base = std::env::var("FORENSIC_SHORTCUTS_BASE").ok();
    let shortcuts_base = args.shortcuts_base.or(env_shortcuts_base.clone().map(PathBuf::from)).unwrap_or_else(crate::default_shortcuts_base);

    let env_lnk_input = std::env::var("FORENSIC_LNK_PATH").ok();
    let lnk_input_explicit = args.lnk_input.is_some() || env_lnk_input.is_some();
    let lnk_input_path = args.lnk_input.or(env_lnk_input.clone().map(PathBuf::from)).unwrap_or_else(|| {
        if !lnk_input_explicit && env_shortcuts_base.is_some() {
            shortcuts_base.clone()
        } else {
            PathBuf::from("exports").join("shortcuts.json")
        }
    });

    let env_browser_input = std::env::var("FORENSIC_BROWSER_PATH").ok();
    let browser_input_path = args.browser_input.or(env_browser_input.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("browser.json"));
    let browser_input_explicit = args.browser_input.is_some() || env_browser_input.is_some();

    let env_rdp_input = std::env::var("FORENSIC_RDP_PATH").ok();
    let rdp_input_path = args.rdp_input.or(env_rdp_input.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("rdp.csv"));
    let rdp_input_explicit = args.rdp_input.is_some() || env_rdp_input.is_some();

    let env_usb_input = std::env::var("FORENSIC_USB_PATH").ok();
    let usb_input_path = args.usb_input.or(env_usb_input.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("usb.json"));
    let usb_input_explicit = args.usb_input.is_some() || env_usb_input.is_some();

    let env_restore_shadow_input = std::env::var("FORENSIC_RESTORE_SHADOW_PATH").ok();
    let restore_shadow_input_path = args.restore_shadow_input.or(env_restore_shadow_input.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("restore_shadow.json"));
    let restore_shadow_input_explicit = args.restore_shadow_input.is_some() || env_restore_shadow_input.is_some();

    let env_user_activity_input = std::env::var("FORENSIC_USER_ACTIVITY_MRU_PATH").ok();
    let user_activity_input_path = args.user_activity_input.or(env_user_activity_input.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("user_activity_mru.json"));
    let user_activity_input_explicit = args.user_activity_input.is_some() || env_user_activity_input.is_some();

    let env_timeline_correlation_input = std::env::var("FORENSIC_TIMELINE_CORRELATION_QA_PATH").ok();
    let timeline_correlation_input_path = args.timeline_correlation_input.or(env_timeline_correlation_input.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("timeline_correlation_qa.json"));
    let timeline_correlation_input_explicit = args.timeline_correlation_input.is_some() || env_timeline_correlation_input.is_some();

    let env_srum_path = std::env::var("FORENSIC_SRUM_PATH").ok();
    let srum_path = args.srum_input.or(env_srum_path.clone().map(PathBuf::from)).unwrap_or_else(crate::default_srum_path);
    let srum_input_explicit = args.srum_input.is_some() || env_srum_path.is_some();

    let env_evtx_security_path = std::env::var("FORENSIC_EVTX_SECURITY_PATH").ok();
    let evtx_security_path = args.evtx_security_input.or(env_evtx_security_path.clone().map(PathBuf::from)).unwrap_or_else(crate::default_evtx_security_path);
    let evtx_security_input_explicit = args.evtx_security_input.is_some() || env_evtx_security_path.is_some();

    let env_evtx_sysmon_path = std::env::var("FORENSIC_EVTX_SYSMON_PATH").ok();
    let evtx_sysmon_path = args.evtx_sysmon_input.or(env_evtx_sysmon_path.clone().map(PathBuf::from)).unwrap_or_else(crate::default_evtx_sysmon_path);
    let evtx_sysmon_input_explicit = args.evtx_sysmon_input.is_some() || env_evtx_sysmon_path.is_some();

    let env_powershell_history_path = std::env::var("FORENSIC_POWERSHELL_HISTORY").ok();
    let powershell_history_path = args.powershell_history.or(env_powershell_history_path.clone().map(PathBuf::from)).unwrap_or_else(crate::default_powershell_history_path);
    let powershell_history_explicit = args.powershell_history.is_some() || env_powershell_history_path.is_some();

    let env_powershell_script_log_path = std::env::var("FORENSIC_POWERSHELL_SCRIPT_LOG").ok();
    let powershell_script_log_path = args.powershell_script_log.or(env_powershell_script_log_path.clone().map(PathBuf::from)).unwrap_or_else(crate::default_powershell_script_log_path);
    let powershell_script_log_explicit = args.powershell_script_log.is_some() || env_powershell_script_log_path.is_some();

    let env_powershell_events_path = std::env::var("FORENSIC_POWERSHELL_EVENTS").ok();
    let powershell_events_path = args.powershell_events.or(env_powershell_events_path.clone().map(PathBuf::from)).unwrap_or_else(crate::default_powershell_events_path);
    let powershell_events_explicit = args.powershell_events.is_some() || env_powershell_events_path.is_some();

    let env_powershell_transcripts_dir = std::env::var("FORENSIC_POWERSHELL_TRANSCRIPTS").ok();
    let powershell_transcripts_dir = args.powershell_transcripts_dir.or(env_powershell_transcripts_dir.clone().map(PathBuf::from)).unwrap_or_else(crate::default_powershell_transcripts_dir);
    let powershell_transcripts_explicit = args.powershell_transcripts_dir.is_some() || env_powershell_transcripts_dir.is_some();

    let env_runmru_reg_path = std::env::var("FORENSIC_RUNMRU_PATH").ok();
    let runmru_reg_path = args.runmru_reg.or(env_runmru_reg_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("runmru.reg"));
    let runmru_reg_explicit = args.runmru_reg.is_some() || env_runmru_reg_path.is_some();

    let env_opensave_reg_path = std::env::var("FORENSIC_OPENSAVE_PATH").ok();
    let opensave_reg_path = args.opensave_reg.or(env_opensave_reg_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("mru2.reg"));
    let opensave_reg_explicit = args.opensave_reg.is_some() || env_opensave_reg_path.is_some();

    let env_userassist_reg_path = std::env::var("FORENSIC_USERASSIST_PATH").ok();
    let userassist_reg_path = args.userassist_reg.or(env_userassist_reg_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("userassist.reg"));
    let userassist_reg_explicit = args.userassist_reg.is_some() || env_userassist_reg_path.is_some();

    let env_recentdocs_reg_path = std::env::var("FORENSIC_RECENTDOCS_PATH").ok();
    let recentdocs_reg_path = args.recentdocs_reg.or(env_recentdocs_reg_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("recentdocs.reg"));
    let recentdocs_reg_explicit = args.recentdocs_reg.is_some() || env_recentdocs_reg_path.is_some();

    let env_autorun_reg_path = std::env::var("FORENSIC_AUTORUN_PATH").ok();
    let autorun_reg_path = args.autorun_reg.or(env_autorun_reg_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("autorun.reg"));
    let autorun_reg_explicit = args.autorun_reg.is_some() || env_autorun_reg_path.is_some();

    let env_bam_reg_path = std::env::var("FORENSIC_BAM_PATH").ok();
    let bam_reg_path = args.bam_reg.or(env_bam_reg_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("bam.reg"));
    let bam_reg_explicit = args.bam_reg.is_some() || env_bam_reg_path.is_some();

    let env_amcache_reg_path = std::env::var("FORENSIC_AMCACHE_PATH").ok();
    let amcache_reg_path = args.amcache_reg.or(env_amcache_reg_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("amcache.reg"));
    let amcache_reg_explicit = args.amcache_reg.is_some() || env_amcache_reg_path.is_some();

    let env_shimcache_reg_path = std::env::var("FORENSIC_SHIMCACHE_PATH").ok();
    let shimcache_reg_path = args.shimcache_reg.or(env_shimcache_reg_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("appcompat.reg"));
    let shimcache_reg_explicit = args.shimcache_reg.is_some() || env_shimcache_reg_path.is_some();

    let env_services_reg_path = std::env::var("FORENSIC_SERVICES_PATH").ok();
    let services_reg_path = args.services_reg.or(env_services_reg_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("services.reg"));
    let services_reg_explicit = args.services_reg.is_some() || env_services_reg_path.is_some();

    let env_tasks_root_path = std::env::var("FORENSIC_TASKS_ROOT").ok();
    let tasks_root_explicit = args.tasks_root.is_some() || env_tasks_root_path.is_some();
    let tasks_root_path = args.tasks_root.or(env_tasks_root_path.clone().map(PathBuf::from));

    let env_wmi_persist_path = std::env::var("FORENSIC_WMI_PERSIST_PATH").ok();
    let wmi_persist_path = args.wmi_persist_input.or(env_wmi_persist_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("artifacts").join("wmi").join("persistence.json"));
    let wmi_persist_explicit = args.wmi_persist_input.is_some() || env_wmi_persist_path.is_some();

    let env_wmi_traces_path = std::env::var("FORENSIC_WMI_TRACES_PATH").ok();
    let wmi_traces_path = args.wmi_traces_input.or(env_wmi_traces_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("artifacts").join("wmi").join("traces.json"));
    let wmi_traces_explicit = args.wmi_traces_input.is_some() || env_wmi_traces_path.is_some();

    let env_wmi_instances_path = std::env::var("FORENSIC_WMI_INSTANCES_PATH").ok();
    let wmi_instances_path = args.wmi_instances_input.or(env_wmi_instances_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("artifacts").join("wmi").join("instances.json"));
    let wmi_instances_explicit = args.wmi_instances_input.is_some() || env_wmi_instances_path.is_some();

    let env_mft_input_path = std::env::var("FORENSIC_MFT_PATH").ok();
    let mft_input_path = args.mft_input.or(env_mft_input_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("mft.json"));
    let mft_input_explicit = args.mft_input.is_some() || env_mft_input_path.is_some();

    let env_usn_input_path = std::env::var("FORENSIC_USN_PATH").ok();
    let usn_input_path = args.usn_input.or(env_usn_input_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("usnjrnl.csv"));
    let usn_input_explicit = args.usn_input.is_some() || env_usn_input_path.is_some();

    let env_logfile_input_path = std::env::var("FORENSIC_LOGFILE_PATH").ok();
    let logfile_input_path = args.logfile_input.or(env_logfile_input_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("logfile.bin"));
    let logfile_input_explicit = args.logfile_input.is_some() || env_logfile_input_path.is_some();

    let env_recycle_input_path = std::env::var("FORENSIC_RECYCLE_BIN_PATH").ok();
    let recycle_input_path = args.recycle_input.or(env_recycle_input_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("recycle_bin.json"));
    let recycle_input_explicit = args.recycle_input.is_some() || env_recycle_input_path.is_some();

    let env_defender_input_path = std::env::var("FORENSIC_DEFENDER_ARTIFACTS_PATH").ok();
    let defender_input_path = args.defender_input.or(env_defender_input_path.clone().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("exports").join("defender_artifacts.json"));
    let defender_input_explicit = args.defender_input.is_some() || env_defender_input_path.is_some();
'''

# Find boundaries
start_idx = content.find("pub fn execute(mut args: Vec<String>) {")
end_idx = content.find("let case_id = match case_id {")

if start_idx == -1 or end_idx == -1:
    print("Could not find boundaries!")
    import sys; sys.exit(1)

new_content = content[:start_idx] + clap_struct + "\npub fn execute(args: TimelineArgs) {" + var_assignments + content[end_idx:]

with open(path, 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f"timeline.rs conversion written!")

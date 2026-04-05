import sys

path = r'd:\forensic-suite\cli\src\commands\execution_correlation.rs'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

start_marker = "pub fn execute(mut args: Vec<String>) {"
end_marker = "    let mut warnings: Vec<String> = Vec::new();"

start_idx = text.find(start_marker)
end_idx = text.find(end_marker)

if start_idx == -1 or end_idx == -1:
    print('Failed to find markers')
    sys.exit(1)

clap_struct = '''use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "execution-correlation", about = "Correlate executable runs across all artifacts")]
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

pub fn execute(args: ExecutionCorrelationArgs) {
    let start_time = std::time::Instant::now();
    let command_name = "execution-correlation".to_string();
    let original_args = vec![]; // Kept for envelope compatibility
    
    let mut limit = args.limit.clamp(1, crate::EXECUTION_CORRELATION_MAX_LIMIT);
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let prefetch_dir = args.prefetch_dir.or(std::env::var("FORENSIC_PREFETCH_DIR").ok().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("C:\\\\Windows\\\\Prefetch"));
    let jumplist_path = args.jumplist_path.or(std::env::var("FORENSIC_JUMPLIST_PATH").ok().map(PathBuf::from)).unwrap_or_else(crate::default_jumplist_path);
    let shortcuts_base = args.shortcuts_base.or(std::env::var("FORENSIC_SHORTCUTS_BASE").ok().map(PathBuf::from)).unwrap_or_else(crate::default_shortcuts_base);
    let lnk_input = args.lnk_input.or(std::env::var("FORENSIC_LNK_PATH").ok().map(PathBuf::from));
    let browser_input = args.browser_input.or(std::env::var("FORENSIC_BROWSER_PATH").ok().map(PathBuf::from));
    let rdp_input = args.rdp_input.or(std::env::var("FORENSIC_RDP_PATH").ok().map(PathBuf::from));
    let usb_input = args.usb_input.or(std::env::var("FORENSIC_USB_PATH").ok().map(PathBuf::from));
    let restore_shadow_input = args.restore_shadow_input.or(std::env::var("FORENSIC_RESTORE_SHADOW_PATH").ok().map(PathBuf::from));
    let user_activity_input = args.user_activity_input.or(std::env::var("FORENSIC_USER_ACTIVITY_MRU_PATH").ok().map(PathBuf::from));
    let timeline_correlation_input = args.timeline_correlation_input.or(std::env::var("FORENSIC_TIMELINE_CORRELATION_QA_PATH").ok().map(PathBuf::from));
    let srum_input = args.srum_input.or(std::env::var("FORENSIC_SRUM_PATH").ok().map(PathBuf::from));
    let evtx_security_input = args.evtx_security_input.or(std::env::var("FORENSIC_EVTX_SECURITY_PATH").ok().map(PathBuf::from));
    let evtx_sysmon_input = args.evtx_sysmon_input.or(std::env::var("FORENSIC_EVTX_SYSMON_PATH").ok().map(PathBuf::from));
    let powershell_history_input = args.powershell_history.or(std::env::var("FORENSIC_POWERSHELL_HISTORY").ok().map(PathBuf::from));
    let powershell_script_log_input = args.powershell_script_log.or(std::env::var("FORENSIC_POWERSHELL_SCRIPT_LOG").ok().map(PathBuf::from));
    let powershell_events_input = args.powershell_events.or(std::env::var("FORENSIC_POWERSHELL_EVENTS").ok().map(PathBuf::from));
    let runmru_reg_input = args.runmru_reg.or(std::env::var("FORENSIC_RUNMRU_PATH").ok().map(PathBuf::from));
    let opensave_reg_input = args.opensave_reg.or(std::env::var("FORENSIC_OPENSAVE_PATH").ok().map(PathBuf::from));
    let userassist_reg_input = args.userassist_reg.or(std::env::var("FORENSIC_USERASSIST_PATH").ok().map(PathBuf::from));
    let recentdocs_reg_input = args.recentdocs_reg.or(std::env::var("FORENSIC_RECENTDOCS_PATH").ok().map(PathBuf::from));
    let autorun_reg_input = args.autorun_reg.or(std::env::var("FORENSIC_AUTORUN_PATH").ok().map(PathBuf::from));
    let bam_reg_input = args.bam_reg.or(std::env::var("FORENSIC_BAM_PATH").ok().map(PathBuf::from));
    let amcache_reg_input = args.amcache_reg.or(std::env::var("FORENSIC_AMCACHE_PATH").ok().map(PathBuf::from));
    let shimcache_reg_input = args.shimcache_reg.or(std::env::var("FORENSIC_SHIMCACHE_PATH").ok().map(PathBuf::from));
    let services_reg_input = args.services_reg.or(std::env::var("FORENSIC_SERVICES_PATH").ok().map(PathBuf::from));
    let tasks_root_input = args.tasks_root.or(std::env::var("FORENSIC_TASKS_ROOT").ok().map(PathBuf::from));
    let wmi_persist_input = args.wmi_persist_input.or(std::env::var("FORENSIC_WMI_PERSIST_PATH").ok().map(PathBuf::from));
    let wmi_traces_input = args.wmi_traces_input.or(std::env::var("FORENSIC_WMI_TRACES_PATH").ok().map(PathBuf::from));
    let wmi_instances_input = args.wmi_instances_input.or(std::env::var("FORENSIC_WMI_INSTANCES_PATH").ok().map(PathBuf::from));
    let mft_input = args.mft_input.or(std::env::var("FORENSIC_MFT_PATH").ok().map(PathBuf::from));
    let usn_input = args.usn_input.or(std::env::var("FORENSIC_USN_PATH").ok().map(PathBuf::from));
    let logfile_input = args.logfile_input.or(std::env::var("FORENSIC_LOGFILE_PATH").ok().map(PathBuf::from));
    let recycle_input = args.recycle_input.or(std::env::var("FORENSIC_RECYCLE_BIN_PATH").ok().map(PathBuf::from));
    let defender_input = args.defender_input.or(std::env::var("FORENSIC_DEFENDER_ARTIFACTS_PATH").ok().map(PathBuf::from));
'''

new_text = text[:start_idx] + clap_struct + "\n" + text[end_idx:]

with open(path, 'w', encoding='utf-8') as f:
    f.write(new_text)

print('Success')

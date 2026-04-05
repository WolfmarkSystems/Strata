import sys

path = r'd:\forensic-suite\cli\src\commands\powershell_artifacts.rs'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

start_marker = "pub fn execute(mut args: Vec<String>) {"
end_marker = "    if limit == 0 {"

start_idx = text.find(start_marker)
end_idx = text.find(end_marker)

if start_idx == -1 or end_idx == -1:
    print('Failed to find markers')
    sys.exit(1)

clap_struct = '''use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "powershell-artifacts", about = "Extract forensic data from PowerShell history, logs, events, and transcripts")]
pub struct PowershellArgs {
    #[arg(long, help = "ConsoleHost_history.txt path")]
    pub history: Option<PathBuf>,

    #[arg(long, help = "script_block.log path")]
    pub script_log: Option<PathBuf>,

    #[arg(long, help = "ps_events.json path")]
    pub events: Option<PathBuf>,

    #[arg(long, help = "transcript directory path")]
    pub transcripts_dir: Option<PathBuf>,

    #[arg(long, help = "modules inventory path")]
    pub modules: Option<PathBuf>,

    #[arg(short, long, default_value_t = crate::POWERSHELL_DEFAULT_LIMIT, help = "Limit records (default: 200, max: 5000)")]
    pub limit: usize,

    #[arg(short, long, help = "Print command payload as JSON")]
    pub json: bool,

    #[arg(long, help = "Write envelope JSON to file")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long, help = "Suppress console summary output")]
    pub quiet: bool,
}

pub fn execute(args: PowershellArgs, command_name: &str, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    
    let history_path = args.history.unwrap_or_else(|| {
        std::env::var("FORENSIC_POWERSHELL_HISTORY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::default_powershell_history_path())
    });

    let script_log_path = args.script_log.unwrap_or_else(|| {
        std::env::var("FORENSIC_POWERSHELL_SCRIPT_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::default_powershell_script_log_path())
    });

    let events_path = args.events.unwrap_or_else(|| {
        std::env::var("FORENSIC_POWERSHELL_EVENTS")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::default_powershell_events_path())
    });

    let transcripts_dir = args.transcripts_dir.unwrap_or_else(|| {
        std::env::var("FORENSIC_POWERSHELL_TRANSCRIPTS")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::default_powershell_transcripts_dir())
    });

    let modules_path = args.modules.unwrap_or_else(|| {
        std::env::var("FORENSIC_POWERSHELL_MODULES")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::default_powershell_modules_path())
    });

    let mut limit = args.limit;
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;
'''

new_text = text[:start_idx] + clap_struct + "\n" + text[end_idx:]

with open(path, 'w', encoding='utf-8') as f:
    f.write(new_text)

print('Success')

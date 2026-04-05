import sys

path = r'd:\forensic-suite\cli\src\commands\wmi_persistence_activity.rs'
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
#[command(name = "wmi-persistence-activity", about = "Extract forensic data from WMI Persistence, Traces, and Instances")]
pub struct WmiArgs {
    #[arg(long, help = "WMI persistence JSON path")]
    pub persist_input: Option<PathBuf>,

    #[arg(long, help = "WMI traces JSON path")]
    pub traces_input: Option<PathBuf>,

    #[arg(long, help = "WMI instances JSON path")]
    pub instances_input: Option<PathBuf>,

    #[arg(short, long, help = "Limit records (default: 200, max: 5000)")]
    pub limit: Option<String>,

    #[arg(short, long, help = "Print command payload as JSON")]
    pub json: bool,

    #[arg(long, help = "Write envelope JSON to file")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long, help = "Suppress console summary output")]
    pub quiet: bool,
}

pub fn execute(args: WmiArgs, command_name: &str, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let persist_input = args.persist_input.unwrap_or_else(|| PathBuf::from("artifacts").join("wmi").join("persistence.json"));
    let traces_input = args.traces_input.unwrap_or_else(|| PathBuf::from("artifacts").join("wmi").join("traces.json"));
    let instances_input = args.instances_input.unwrap_or_else(|| PathBuf::from("artifacts").join("wmi").join("instances.json"));

    let mut limit = match args.limit {
        Some(limit_str) => match limit_str.parse::<usize>() {
            Ok(parsed) => parsed,
            Err(_) => {
                let err_msg = format!("Error: Invalid --limit '{}'", limit_str);
                if let Some(ref json_path) = json_result_path {
                    let envelope = crate::envelope::CliResultEnvelope::new(
                        "wmi-persistence-activity",
                        original_args.clone(),
                        crate::envelope::EXIT_VALIDATION,
                        start_time.elapsed().as_millis() as u64,
                    )
                    .error(err_msg.clone())
                    .with_error_type("invalid_input")
                    .with_hint("Use --limit <N> with a numeric value");
                    let _ = envelope.write_to_file(json_path);
                }
                if !quiet {
                    eprintln!("{}", err_msg);
                }
                std::process::exit(crate::envelope::EXIT_VALIDATION);
            }
        },
        None => crate::WMI_PERSISTENCE_DEFAULT_LIMIT,
    };
'''

new_text = text[:start_idx] + clap_struct + "\n" + text[end_idx:]

with open(path, 'w', encoding='utf-8') as f:
    f.write(new_text)

print('Success')

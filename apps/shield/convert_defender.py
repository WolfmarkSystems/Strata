import sys

path = r'd:\forensic-suite\cli\src\commands\defender_artifacts.rs'
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
#[command(name = "defender-artifacts", about = "Reads Defender-related artifacts from default/env-configured paths")]
pub struct DefenderArgs {
    #[arg(short, long, help = "Limit records returned per collection (default: 200, max: 5000)")]
    pub limit: Option<String>,

    #[arg(short, long, help = "Print command payload as JSON")]
    pub json: bool,

    #[arg(long, help = "Write envelope JSON to file")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long, help = "Suppress console summary output")]
    pub quiet: bool,
}

pub fn execute(args: DefenderArgs, command_name: &str, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let mut limit = match args.limit {
        Some(limit_str) => match limit_str.parse::<usize>() {
            Ok(parsed) => parsed,
            Err(_) => {
                let err_msg = format!("Error: Invalid --limit '{}'", limit_str);
                if let Some(ref json_path) = json_result_path {
                    let envelope = crate::envelope::CliResultEnvelope::new(
                        "defender-artifacts",
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
        None => crate::DEFENDER_ARTIFACTS_DEFAULT_LIMIT,
    };
'''

new_text = text[:start_idx] + clap_struct + "\n" + text[end_idx:]

with open(path, 'w', encoding='utf-8') as f:
    f.write(new_text)

print('Success')

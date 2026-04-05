// Extracted from main.rs — run_carve_command
// TODO: Convert to clap derive args in a future pass

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "carve", about = "Run carving scan operations")]
pub struct CarveArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn execute(args: CarveArgs) {
    let mut command_args = vec!["carve".to_string()];
    command_args.extend(args.args);
    execute_legacy(command_args);
}

fn execute_legacy(mut args: Vec<String>) {
    args.remove(0);

    let mut case_id: Option<String> = None;
    let mut evidence_id: Option<String> = None;
    let mut volume_id: Option<String> = None;
    let mut signatures: Vec<String> = Vec::new();
    let mut max_hits: Option<usize> = None;
    let mut _inline = false;
    let mut _json_output = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--case" | "-c" => {
                if i + 1 < args.len() {
                    case_id = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--evidence" | "-e" => {
                if i + 1 < args.len() {
                    evidence_id = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--volume" | "-v" => {
                if i + 1 < args.len() {
                    volume_id = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--sig" | "-s" => {
                if i + 1 < args.len() {
                    for sig in args[i + 1].split(',') {
                        signatures.push(sig.trim().to_string());
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--max-hits" => {
                if i + 1 < args.len() {
                    max_hits = args[i + 1].parse().ok();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--inline" => {
                _inline = true;
                i += 1;
            }
            "--json" | "-j" => {
                _json_output = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!("Usage: forensic-cli carve [options]");
                println!();
                println!("Options:");
                println!("  --case, -c ID       Case ID");
                println!("  --evidence, -e ID  Evidence ID to carve");
                println!("  --volume, -v ID    Volume ID (optional)");
                println!(
                    "  --sig, -s NAMES     Signatures to scan (comma-separated, e.g., JPEG,PNG)"
                );
                println!("  --max-hits N        Maximum hits (default: 5000)");
                println!("  --inline            Run inline (for testing)");
                println!("  --json, -j         Output as JSON");
                std::process::exit(0);
            }
            _ => i += 1,
        }
    }

    let case_id = match case_id {
        Some(id) => id,
        None => {
            eprintln!("Error: --case is required");
            std::process::exit(1);
        }
    };

    let evidence_id = match evidence_id {
        Some(id) => id,
        None => {
            eprintln!("Error: --evidence is required");
            std::process::exit(1);
        }
    };

    println!("=== Carving Scan ===");
    println!("Case: {}", case_id);
    println!("Evidence: {}", evidence_id);
    if let Some(vid) = &volume_id {
        println!("Volume: {}", vid);
    }
    if !signatures.is_empty() {
        println!("Signatures: {:?}", signatures);
    }
    if let Some(mh) = max_hits {
        println!("Max hits: {}", mh);
    }
    println!("Mode: {}", if _inline { "inline" } else { "job" });

    if _inline {
        println!("\nNote: Inline carving requires container access.");
        println!("This would run the carving algorithm directly.");
    } else {
        println!("\nNote: Job queuing not fully implemented in this demo.");
    }

    println!();
    println!("Available signatures:");
    println!("  JPEG, PNG, GIF, PDF, ZIP, DOCX, XLSX, PPTX, RTF, MP3, AVI, MP4");
}

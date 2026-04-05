use crate::envelope::{CliResultEnvelope, EXIT_ERROR, EXIT_OK};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "doctor",
    about = "Run system diagnostics and environment checks"
)]
pub struct DoctorArgs {
    #[arg(short, long, help = "Directory to write diagnostics bundle")]
    pub bundle: Option<String>,

    #[arg(short, long, help = "Enable verbose output")]
    pub verbose: bool,

    #[arg(long = "json-result", help = "Path to write JSON result envelope")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long, help = "Suppress console output")]
    pub quiet: bool,
}

pub fn execute(args: DoctorArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let platform = {
        #[cfg(target_os = "windows")]
        {
            let mut webview2_found = false;

            use std::process::Command;

            let webview2_keys = [
                r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
                r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
            ];

            for key in &webview2_keys {
                let output = Command::new("reg")
                    .args(["query", &format!("HKLM\\{}", key), "/v", "pv"])
                    .output();

                if let Ok(output) = output {
                    if output.status.success()
                        && String::from_utf8_lossy(&output.stdout).contains("REG_SZ")
                    {
                        webview2_found = true;
                        break;
                    }
                }
            }

            ("windows".to_string(), webview2_found)
        }
        #[cfg(not(target_os = "windows"))]
        {
            ("non-windows".to_string(), false)
        }
    };
    let (platform_str, webview2_found) = platform;

    if !args.quiet {
        println!("=== Forensic Suite Diagnostics ===");
        println!();
        println!("Version: {}", env!("CARGO_PKG_VERSION"));
        println!();

        #[cfg(target_os = "windows")]
        {
            println!("Platform: Windows");
            println!(
                "WebView2: {}",
                if webview2_found {
                    "Found"
                } else {
                    "NOT FOUND (required for desktop UI)"
                }
            );
        }

        #[cfg(not(target_os = "windows"))]
        {
            println!("Platform: Non-Windows");
        }

        println!();

        if let Some(ref dir) = args.bundle {
            println!("Generating diagnostics bundle...");
            let db_path = PathBuf::from(dir).join("diagnostics_temp.sqlite");
            if let Ok(conn) = rusqlite::Connection::open(&db_path) {
                let check: Result<String, _> =
                    conn.query_row("PRAGMA integrity_check", [], |row| row.get(0));
                if let Ok(_result) = check {
                    println!("SQLite: OK");
                }
                let _ = std::fs::remove_file(&db_path);
            }
            println!("Bundle would be created at: {}", dir);
            println!("(Full bundle generation requires desktop app)");
        }

        println!();
        println!("Run 'forensic_cli --help' for CLI commands.");
        println!("Run 'forensic_desktop --safe-mode' for safe mode diagnostics.");
    }

    let elapsed_ms = start_time.elapsed().as_millis() as u64;

    if let Some(json_path) = args.json_result {
        let diagnostic_data = serde_json::json!({
            "platform": platform_str,
            "webview2_found": webview2_found,
            "tool_version": env!("CARGO_PKG_VERSION")
        });

        let result = CliResultEnvelope::new("doctor", original_args, EXIT_OK, elapsed_ms)
            .with_data(diagnostic_data);

        if let Err(e) = result.write_to_file(&json_path) {
            eprintln!("Error writing JSON result: {}", e);
            std::process::exit(EXIT_ERROR);
        }
    }
}

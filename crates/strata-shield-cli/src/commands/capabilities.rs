use crate::envelope::{CliResultEnvelope, EXIT_ERROR, EXIT_OK};
use clap::Parser;
use forensic_engine::capabilities::get_capabilities_report;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "capabilities", about = "Show forensic suite capabilities")]
pub struct CapabilitiesArgs {
    #[arg(short, long)]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(short, long)]
    pub quiet: bool,
}

pub fn execute(args: CapabilitiesArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let report = get_capabilities_report();
    let elapsed_ms = start_time.elapsed().as_millis() as u64;

    if args.json || args.json_result.is_some() {
        if !args.quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
        }
    } else {
        println!("=== Forensic Suite Capabilities ===");
        println!("Tool Version: {}", report.tool_version);
        println!("Generated: {}", report.generated_utc);
        println!();
        println!("{:<45} {:<15} {:<15}", "Capability", "Status", "Platforms");
        println!("{}", "-".repeat(80));

        for cap in &report.capabilities {
            let platforms = cap.platforms.join(",");
            println!(
                "{:<45} {:<15} {:<15}",
                cap.name,
                format!("{:?}", cap.status),
                platforms
            );
        }

        println!();
        println!("Status Legend:");
        println!("  Production   - Fully supported and tested");
        println!("  Beta         - Supported with limited testing");
        println!("  Experimental - Under development");
        println!("  Stub         - Basic/stub implementation");
        println!("  Unsupported  - Not yet available");
    }

    if let Some(json_path) = args.json_result {
        let caps_json: Vec<serde_json::Value> = report
            .capabilities
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "status": format!("{:?}", c.status).to_lowercase(),
                    "platforms": c.platforms,
                    "description": c.description
                })
            })
            .collect();

        let result = CliResultEnvelope::new("capabilities", original_args, EXIT_OK, elapsed_ms)
            .with_data(serde_json::json!({
                "capabilities": caps_json,
                "tool_version": report.tool_version,
                "generated_utc": report.generated_utc
            }));

        if let Err(e) = result.write_to_file(&json_path) {
            eprintln!("Error writing JSON result: {}", e);
            std::process::exit(EXIT_ERROR);
        }
    }
}

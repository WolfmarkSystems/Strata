// Extracted from main.rs - run_unallocated_command

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "unallocated", about = "Inspect unallocated regions")]
pub struct UnallocatedArgs {
    #[arg(long = "case", short = 'c', help = "Case ID")]
    pub case: String,

    #[arg(long = "volume", short = 'v', help = "Volume ID")]
    pub volume: String,

    #[arg(long = "coalesce-gap", default_value_t = 1024 * 1024, help = "Gap threshold for coalescing")]
    pub coalesce_gap: u64,

    #[arg(long = "json", short = 'j', help = "Output as JSON")]
    pub json_output: bool,
}

pub fn execute(args: UnallocatedArgs) {
    println!("=== Unallocated Regions ===");
    println!("Case: {}", args.case);
    println!("Volume: {}", args.volume);
    println!("Coalesce gap: {} bytes", args.coalesce_gap);
    println!(
        "Output format: {}",
        if args.json_output { "json" } else { "text" }
    );
    println!();
    println!("Note: This requires filesystem analysis to be run first.");
    println!("Supported filesystems:");
    println!("  - NTFS (Production): Uses $Bitmap");
    println!("  - exFAT (Experimental): Best-effort");
    println!("  - ext4 (Beta): Block bitmap analysis");
    println!("  - APFS (Experimental): Space manager not implemented");
}

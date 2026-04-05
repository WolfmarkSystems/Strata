use clap::Parser;
use forensic_engine::evidence::EvidenceOpener;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "open-evidence", about = "Open and analyze an evidence source")]
pub struct OpenEvidenceArgs {
    #[arg(help = "Path to the evidence source")]
    pub path: Option<String>,

    #[arg(short, long, help = "Output in JSON format")]
    pub json: bool,

    #[arg(short = 'c', long = "case-id", help = "Case ID for the evidence")]
    pub case_id: Option<String>,

    #[arg(
        short,
        long,
        help = "Username for activity log (default: current user)"
    )]
    pub user: Option<String>,
}

pub fn execute(args: OpenEvidenceArgs) {
    let user_name = args.user.unwrap_or_else(whoami::username);

    let source_path = match args.path {
        Some(ref p) => {
            let path = PathBuf::from(p);
            if !path.exists() {
                eprintln!("Error: Path does not exist: {}", path.display());
                std::process::exit(1);
            }
            path
        }
        None => {
            eprintln!("Error: No path provided. Usage: forensic-cli open-evidence <path>");
            std::process::exit(1);
        }
    };

    let case_id_str = args
        .case_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let opener = EvidenceOpener::new(&case_id_str, &user_name);

    match opener.open_evidence(&source_path) {
        Ok(detection) => {
            if args.json {
                println!("{}", detection.to_json().unwrap_or_default());
            } else {
                println!("=== Evidence Detection Report ===");
                println!("Evidence ID: {}", detection.evidence_id);
                println!("Source Path: {}", detection.source_path);
                println!("Detected At: {}", detection.detection_timestamp_utc);
                println!();

                if let Some(container) = &detection.container_type {
                    println!("Container:");
                    println!("  Type: {}", container.container_type);
                    println!("  Size: {} bytes", container.size_bytes);
                    println!("  Sector Size: {} bytes", container.sector_size);
                    println!("  Supported: {}", container.is_supported);
                    println!("  Capability: {}", container.capability_name);
                    println!();
                }

                if let Some(partition) = &detection.partition_scheme {
                    println!("Partition Scheme:");
                    println!("  Scheme: {}", partition.scheme);
                    println!("  Partitions: {}", partition.partition_count);
                    println!("  Supported: {}", partition.is_supported);
                    println!("  Capability: {}", partition.capability_name);
                    println!();
                }

                if !detection.volumes.is_empty() {
                    println!("Volumes ({} detected):", detection.volumes.len());
                    for vol in &detection.volumes {
                        println!("  Volume {}:", vol.index);
                        println!("    Offset: {} bytes", vol.offset_bytes);
                        println!("    Size: {} bytes", vol.size_bytes);
                        println!("    Supported: {}", vol.is_supported);
                        if let Some(fs) = &vol.filesystem {
                            println!("    Filesystem: {}", fs.filesystem_type);
                            println!("    FS Supported: {}", fs.is_supported);
                            println!("    FS Capability: {}", fs.capability_name);
                        }
                    }
                    println!();
                }

                println!("Capability Checks:");
                println!("  Satisfied: {}", detection.supported_count());
                println!("  Unsatisfied: {}", detection.unsupported_count());

                if !detection.warnings.is_empty() {
                    println!();
                    println!("Warnings:");
                    for warning in &detection.warnings {
                        println!("  - {}", warning);
                    }
                }

                if !detection.errors.is_empty() {
                    println!();
                    println!("Errors:");
                    for error in &detection.errors {
                        println!("  - {}", error);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error opening evidence: {}", e);
            std::process::exit(1);
        }
    }
}

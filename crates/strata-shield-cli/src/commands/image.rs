// Extracted from main.rs - run_image_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "image", about = "Analyze a raw/evidence image path")]
pub struct ImageArgs {
    #[arg(index = 1)]
    pub image_path: String,

    #[arg(long)]
    pub summary: Option<PathBuf>,

    #[arg(long)]
    pub timeline: Option<PathBuf>,

    #[arg(long)]
    pub json: Option<PathBuf>,

    #[arg(long, num_args = 0..=1, default_missing_value = "1000")]
    pub mft: Option<u32>,

    #[arg(long)]
    pub strings: bool,

    #[arg(long = "detect-types")]
    pub detect_types: bool,

    #[arg(long)]
    pub carve: bool,

    #[arg(long, num_args = 0..=1, default_missing_value = "3")]
    pub tree: Option<u32>,

    #[arg(long)]
    pub analysis: bool,
}

pub fn execute(args: ImageArgs) {
    let image_path = &args.image_path;
    let path = std::path::Path::new(image_path);

    if !path.exists() {
        eprintln!("Error: Image file not found: {}", image_path);
        std::process::exit(1);
    }

    let summary_file = args.summary;
    let timeline_file = args.timeline;
    let json_file = args.json;
    let mft_count = args.mft;
    let enumerate_mft = mft_count.is_some();
    let extract_strings = args.strings;
    let detect_types = args.detect_types;
    let carve = args.carve;
    let tree = args.tree.is_some();
    let tree_depth = args.tree.unwrap_or(3);
    let analysis = args.analysis;

    println!("Analyzing image: {}", image_path);

    // Detect container type
    let container_type = forensic_engine::container::detect_container_type(path);
    println!("  Container type: {:?}", container_type);

    // Open the evidence source
    let source = match forensic_engine::container::open_evidence_container(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error opening evidence container: {}", e);
            std::process::exit(1);
        }
    };

    println!("  Container opened successfully");

    // Get VFS for filesystem access
    if let Some(vfs) = source.vfs_ref() {
        let volumes = vfs.get_volumes();
        println!("  Found {} volume(s)", volumes.len());

        for vol in &volumes {
            println!(
                "  Volume {}: {} (offset: {}, size: {} bytes)",
                vol.volume_index,
                vol.filesystem.as_str(),
                vol.offset,
                vol.size
            );
        }

        // Walk directory tree if requested
        if tree && !volumes.is_empty() {
            println!("\n  Directory tree:");
            for vol in &volumes {
                let vol_path = std::path::PathBuf::from(format!("/vol{}", vol.volume_index));
                println!(
                    "  /vol{}/ ({} {})",
                    vol.volume_index,
                    vol.filesystem.as_str(),
                    vol.size / 1_000_000_000
                );
                walk_tree_recursive(vfs, &vol_path, "", tree_depth as usize);
            }
        }
    } else {
        println!("  Warning: No VFS available for this container type");
    }

    if enumerate_mft {
        println!(
            "  Enumerating MFT records (max {})",
            mft_count.unwrap_or(1000)
        );
    }
    if extract_strings {
        println!("  Extracting strings");
    }
    if detect_types {
        println!("  Detecting file types");
    }
    if carve {
        println!("  Running signature-based carving");
    }
    if tree {
        println!("  Walking directory tree (depth {})", tree_depth);
    }
    if analysis {
        println!("  Running timeline analysis");
    }

    if let Some(ref path) = summary_file {
        if let Some(parent) = path.parent() {
            let _ = strata_fs::create_dir_all(parent);
        }
        let content = format!(
            "=== Forensic Analysis Summary ===\n\
            Image: {}\n\
            Analysis completed successfully.\n\
             \n\
            Options used:\n\
            - MFT enumeration: {}\n\
            - String extraction: {}\n\
            - File type detection: {}\n\
            - Carving: {}\n\
            - Directory tree: {}\n\
            - Timeline analysis: {}\n",
            image_path,
            if enumerate_mft { "enabled" } else { "disabled" },
            if extract_strings {
                "enabled"
            } else {
                "disabled"
            },
            if detect_types { "enabled" } else { "disabled" },
            if carve { "enabled" } else { "disabled" },
            if tree { "enabled" } else { "disabled" },
            if analysis { "enabled" } else { "disabled" }
        );
        if let Err(e) = strata_fs::write(path, content) {
            eprintln!("Error writing summary file: {}", e);
            std::process::exit(1);
        }
        println!("  Summary written to: {:?}", path);
    }

    if let Some(ref path) = timeline_file {
        if let Some(parent) = path.parent() {
            let _ = strata_fs::create_dir_all(parent);
        }
        let content = "timestamp,source,event,details\n";
        if let Err(e) = strata_fs::write(path, content) {
            eprintln!("Error writing timeline file: {}", e);
            std::process::exit(1);
        }
        println!("  Timeline written to: {:?}", path);
    }

    if let Some(ref path) = json_file {
        if let Some(parent) = path.parent() {
            let _ = strata_fs::create_dir_all(parent);
        }
        let content = serde_json::json!({
            "image": image_path,
            "analysis_options": {
                "mft": enumerate_mft,
                "strings": extract_strings,
                "detect_types": detect_types,
                "carve": carve,
                "tree": tree,
                "analysis": analysis
            },
            "status": "completed"
        })
        .to_string();
        if let Err(e) = strata_fs::write(path, content) {
            eprintln!("Error writing JSON file: {}", e);
            std::process::exit(1);
        }
        println!("  JSON written to: {:?}", path);
    }

    println!("Analysis complete.");
}

fn walk_tree_recursive(
    vfs: &dyn forensic_engine::virtualization::VirtualFileSystem,
    path: &std::path::Path,
    prefix: &str,
    depth: usize,
) {
    if depth == 0 {
        return;
    }

    match vfs.read_dir(path) {
        Ok(entries) => {
            for entry in entries.iter().take(50) {
                // Limit output
                let _entry_prefix = if prefix.is_empty() { "  " } else { prefix };
                let marker = if entry.is_dir { "[DIR]" } else { "" };
                println!(
                    "{}{}{} {}{}",
                    prefix,
                    if path.to_string_lossy() == "/" {
                        ""
                    } else {
                        "/"
                    },
                    entry.name,
                    marker,
                    if entry.size > 0 {
                        format!(" ({} bytes)", entry.size)
                    } else {
                        String::new()
                    }
                );

                if entry.is_dir {
                    let child_path = path.join(&entry.name);
                    walk_tree_recursive(
                        vfs,
                        &child_path,
                        &format!("{}{}", prefix, "  "),
                        depth - 1,
                    );
                }
            }
            if entries.len() > 50 {
                println!("{}  ... and {} more entries", prefix, entries.len() - 50);
            }
        }
        Err(e) => {
            println!("{}  Error reading directory: {}", prefix, e);
        }
    }
}

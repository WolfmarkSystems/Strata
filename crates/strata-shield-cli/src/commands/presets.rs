use crate::{get_examiner_preset, init_case_schema, init_default_presets, list_examiner_presets};
use clap::Parser;
use clap::Subcommand;

#[derive(Parser, Debug)]
#[command(name = "presets", about = "Manage examiner presets")]
pub struct PresetsArgs {
    #[command(subcommand)]
    pub command: Option<PresetsCommand>,
}

#[derive(Subcommand, Debug)]
pub enum PresetsCommand {
    /// List all available presets
    List,
    /// Show details of a specific preset
    Show {
        #[arg(long, help = "Name of the preset to show")]
        name: String,
    },
}

pub fn execute(args: PresetsArgs) {
    let temp_dir = std::env::temp_dir().join(format!("forensic-cli-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let conn = rusqlite::Connection::open(temp_dir.join("temp.db")).unwrap();

    init_case_schema(&conn).ok();
    init_default_presets(&conn).ok();

    match args.command.unwrap_or(PresetsCommand::List) {
        PresetsCommand::List => {
            let presets = list_examiner_presets(&conn).unwrap_or_default();
            if presets.is_empty() {
                eprintln!("No presets found in DB (unexpected)");
                std::process::exit(1);
            }
            println!("=== Available Examiner Presets ===");
            println!();
            for preset in presets {
                println!("{}", preset.name);
                println!("  {}", preset.description);
                println!();
            }
        }
        PresetsCommand::Show { name } => {
            if let Some(details) = get_examiner_preset(&conn, &name).unwrap_or(None) {
                println!("=== Preset: {} ===", name);
                println!();
                println!("JSON Configuration:");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&details.preset_json).unwrap_or_default()
                );
                println!();
                println!("Locked Keys (cannot be overridden):");
                for key in &details.locked_keys_json {
                    println!("  - {}", key);
                }
            } else {
                println!("Preset not found: {}", name);
                std::process::exit(1);
            }
        }
    }
}

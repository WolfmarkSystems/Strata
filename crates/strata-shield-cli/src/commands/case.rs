// Extracted from main.rs - run_case_command

use crate::*;
use clap::Parser;
use clap::Subcommand;

#[derive(Parser, Debug)]
#[command(name = "case", about = "Case management commands")]
pub struct CaseArgs {
    #[command(subcommand)]
    pub command: Option<CaseCommand>,
}

#[derive(Subcommand, Debug)]
pub enum CaseCommand {
    Init(CaseInitArgs),
    #[command(name = "set-auto-preset")]
    SetAutoPreset(CaseAutoPresetArgs),
}

#[derive(Parser, Debug)]
pub struct CaseInitArgs {
    #[arg(short, long)]
    pub case: Option<String>,

    #[arg(short, long)]
    pub db: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct CaseAutoPresetArgs {
    #[arg(short, long)]
    pub case: Option<String>,

    #[arg(short, long)]
    pub db: Option<PathBuf>,

    #[arg(short = 'p', long = "preset")]
    pub preset: Option<String>,
}

pub fn execute(args: CaseArgs) {
    match args.command {
        Some(CaseCommand::Init(cmd)) => run_init(cmd),
        Some(CaseCommand::SetAutoPreset(cmd)) => run_set_auto_preset(cmd),
        None => {
            println!("Unknown case subcommand: ");
            println!("Use: case set-auto-preset --case <id> --db <path> --preset <name>|none");
            std::process::exit(1);
        }
    }
}

fn run_init(args: CaseInitArgs) {
    let case_id = args.case.unwrap_or_else(|| {
        println!("Error: --case <id> required");
        std::process::exit(1);
    });

    let db_path = args.db.unwrap_or_else(|| {
        println!("Error: --db <path> required");
        std::process::exit(1);
    });

    let conn = open_case_db(&db_path);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let result = conn.execute(
        "INSERT OR IGNORE INTO cases (id, name, examiner, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![&case_id, "New Case", "default", now, now],
    );

    match result {
        Ok(_) => {
            println!("Created case: {}", case_id);
            println!("Database: {:?}", db_path);
        }
        Err(e) => {
            println!("Warning: Could not create case row: {}", e);
        }
    }

    println!("Case initialized successfully.");
}

fn run_set_auto_preset(args: CaseAutoPresetArgs) {
    let case_id = args.case.unwrap_or_else(|| {
        println!("Error: --case <id> required");
        std::process::exit(1);
    });

    let db_path = args.db.unwrap_or_else(|| {
        println!("Error: --db <path> required");
        std::process::exit(1);
    });

    let preset = args
        .preset
        .and_then(|p| if p == "none" { None } else { Some(p) });

    let conn = open_case_db(&db_path);

    match set_auto_start_preset(&conn, &case_id, preset.as_deref()) {
        Ok(_) => {
            if let Some(ref p) = preset {
                println!("Set auto-start preset to: {}", p);
            } else {
                println!("Cleared auto-start preset");
            }
        }
        Err(e) => {
            println!("Error setting preset: {}", e);
            std::process::exit(1);
        }
    }
}

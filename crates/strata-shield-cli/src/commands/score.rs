use clap::Parser;
use clap::Subcommand;
use forensic_engine::case::database::CaseDatabase;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "score", about = "Manage file scoring and relevance ranking")]
pub struct ScoreArgs {
    #[command(subcommand)]
    pub command: Option<ScoreCommand>,

    #[arg(short, long, help = "Case ID (required)")]
    pub case: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ScoreCommand {
    /// Rebuild all file scores for a case
    Rebuild,
    /// Explain the scoring for a specific row
    Explain {
        #[arg(short, long = "row-id", help = "Row ID to explain")]
        row_id: i64,
    },
}

pub fn execute(args: ScoreArgs) {
    let case_id = match args.case {
        Some(id) => id,
        None => {
            eprintln!("Error: --case is required");
            std::process::exit(1);
        }
    };

    let db_path = PathBuf::from("./forensic.db");
    if !db_path.exists() {
        eprintln!("Error: Database not found at {}", db_path.display());
        std::process::exit(1);
    }

    let db = match CaseDatabase::open(&case_id, &db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Error opening database: {}", e);
            std::process::exit(1);
        }
    };

    match args.command.unwrap_or(ScoreCommand::Rebuild) {
        ScoreCommand::Rebuild => {
            println!("=== Score Rebuild ===");
            println!("Case: {}", case_id);

            match db.recompute_scores(&case_id, None) {
                Ok(updated) => {
                    println!("Updated {} file scores.", updated);
                }
                Err(e) => {
                    eprintln!("Error rebuilding scores: {}", e);
                    std::process::exit(1);
                }
            }
        }
        ScoreCommand::Explain { row_id } => {
            println!("=== Score Explanation ===");
            println!("Case: {}", case_id);
            println!("Row ID: {}", row_id);

            match db.explain_file_table_score(&case_id, row_id) {
                Ok(result) => {
                    println!("Score: {:.2}", result.score);
                    println!("Signals:");
                    for signal in &result.signals {
                        println!(
                            "  +{:.2} {} - {}",
                            signal.points, signal.key, signal.evidence
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Error explaining score: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

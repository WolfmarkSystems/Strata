use clap::Parser;
use clap::Subcommand;
use forensic_engine::case::database::CaseDatabase;
use forensic_engine::container::IngestRegistry;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ingest",
    about = "Ingest diagnostics and compatibility commands"
)]
pub struct IngestArgs {
    #[command(subcommand)]
    pub command: IngestSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum IngestSubcommand {
    Doctor(IngestDoctorArgs),
    Inspect(IngestInspectArgs),
    Matrix(IngestMatrixArgs),
}

#[derive(Parser, Debug)]
pub struct IngestDoctorArgs {
    #[arg(long, help = "Path to evidence source")]
    pub input: String,

    #[arg(long, help = "Print JSON output")]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct IngestInspectArgs {
    #[arg(long, help = "Case ID")]
    pub case: String,

    #[arg(long, help = "Path to case database")]
    pub db: PathBuf,

    #[arg(long, default_value_t = 100, help = "Max ingest manifests")]
    pub limit: usize,

    #[arg(long, help = "Print JSON output")]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct IngestMatrixArgs {
    #[arg(long, help = "Print JSON output")]
    pub json: bool,
}

#[derive(Serialize)]
struct IngestDoctorOutput {
    input_path: String,
    container_type: String,
    parser_adapter: String,
    source_hint: String,
    profile: Option<serde_json::Value>,
}

pub fn execute(args: IngestArgs) {
    match args.command {
        IngestSubcommand::Doctor(cmd) => {
            let path = PathBuf::from(&cmd.input);
            if !path.exists() {
                eprintln!("Error: input path does not exist: {}", path.display());
                std::process::exit(1);
            }
            let desc = IngestRegistry::detect(&path);
            let output = IngestDoctorOutput {
                input_path: path.display().to_string(),
                container_type: desc.container_type.as_str().to_string(),
                parser_adapter: desc.parser_adapter,
                source_hint: desc.source_hint,
                profile: desc.profile.map(|p| serde_json::json!(p)),
            };
            if cmd.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
                return;
            }
            println!("=== Ingest Doctor ===");
            println!("Input: {}", output.input_path);
            println!("Container: {}", output.container_type);
            println!("Adapter: {}", output.parser_adapter);
            println!("Source Hint: {}", output.source_hint);
            if let Some(profile) = output.profile {
                println!("Profile: {}", profile);
            }
        }
        IngestSubcommand::Inspect(cmd) => {
            let db = match CaseDatabase::open(&cmd.case, &cmd.db) {
                Ok(db) => db,
                Err(err) => {
                    eprintln!("Failed to open case DB: {}", err);
                    std::process::exit(1);
                }
            };
            let rows = match db.list_ingest_manifests(cmd.limit) {
                Ok(rows) => rows,
                Err(err) => {
                    eprintln!("Failed to list ingest manifests: {}", err);
                    std::process::exit(1);
                }
            };
            if cmd.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string())
                );
                return;
            }
            println!("=== Ingest Inspect ===");
            println!("Case: {}", cmd.case);
            println!("Rows: {}", rows.len());
            for row in rows {
                println!(
                    "- {} | {} | {}:{} | warnings={} unsupported={}",
                    row.source_path,
                    row.container_type,
                    row.parser_name,
                    row.parser_version,
                    row.warning_count,
                    row.unsupported_count
                );
            }
        }
        IngestSubcommand::Matrix(cmd) => {
            let rows = IngestRegistry::compatibility_matrix_rows();
            if cmd.json {
                let json: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|(format, status, adapter)| {
                        serde_json::json!({ "format": format, "status": status, "adapter": adapter })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json).unwrap_or_else(|_| "[]".to_string())
                );
                return;
            }
            println!("=== Ingestion Compatibility Matrix ===");
            for (format, status, adapter) in rows {
                println!("- {:<24} {:<10} {}", format, status, adapter);
            }
        }
    }
}

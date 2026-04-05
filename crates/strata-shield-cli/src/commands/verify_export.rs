// Extracted from main.rs - run_verify_export_command

use crate::{
    check_export_guard, verify_case, write_verification_artifacts, ExportOptions, VerifyOptions,
};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "verify-export",
    about = "Run verification then export in one step"
)]
pub struct VerifyExportArgs {
    #[arg(long = "case", short = 'c')]
    pub case: String,

    #[arg(long = "db", short = 'd')]
    pub db: PathBuf,

    #[arg(long = "output", short = 'o')]
    pub output: Option<PathBuf>,

    #[arg(long = "sample", short = 's')]
    pub sample: Option<u64>,

    #[arg(long = "strict")]
    pub strict: bool,

    #[arg(long = "max-age", short = 'm')]
    pub max_age: Option<u64>,
}

pub fn execute(args: VerifyExportArgs) {
    let case_id = args.case;
    let db_path = args.db;
    let output_dir = args
        .output
        .unwrap_or_else(|| PathBuf::from(format!("./export_{}", case_id)));
    let sample = args.sample;
    let strict = args.strict;
    let max_age = args.max_age;

    println!("Running verification for case: {}", case_id);

    let verify_opts = VerifyOptions {
        verify_activity_hash_chain: true,
        verify_packet_manifests: true,
        verify_db_integrity: true,
        verify_read_models_rebuild: true,
        verify_timeline_idempotency: true,
        verify_fts_queue_empty: false,
        sample_limit: sample,
    };

    let report = match verify_case(&case_id, &db_path, verify_opts) {
        Ok(r) => r,
        Err(e) => {
            println!("Verification failed: {}", e);
            std::process::exit(1);
        }
    };

    println!("Verification complete: {:?}\n", report.status);

    let export_options = ExportOptions {
        require_verification: true,
        max_report_age_seconds: max_age,
        allow_warn: !strict,
    };

    let mut conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            println!("Error opening database: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = check_export_guard(&mut conn, &case_id, &export_options) {
        println!("Export blocked: {}", e.message);
        std::process::exit(1);
    }

    if let Err(e) = strata_fs::create_dir_all(&output_dir) {
        println!("Error creating output directory: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = write_verification_artifacts(&output_dir, &case_id, Some(&report)) {
        println!("Failed to write verification artifacts: {}", e);
    }

    let export_summary_path = output_dir.join("export_summary.txt");
    let mut summary = String::new();
    summary.push_str(&format!("Case: {}\n", case_id));
    summary.push_str(&format!(
        "Export Time: {}\n",
        chrono::Utc::now().to_rfc3339()
    ));
    summary.push_str("Verification Status: ");
    summary.push_str(&format!("{:?}\n", report.status));

    if let Err(e) = strata_fs::write(&export_summary_path, &summary) {
        println!("Error writing export summary: {}", e);
    }

    println!("Export artifacts written to: {}", output_dir.display());
    println!("Verification artifacts written:");
    println!("  - verification_report.latest.json");
    println!("  - verification_summary.txt");
    println!("  - export_summary.txt");
}

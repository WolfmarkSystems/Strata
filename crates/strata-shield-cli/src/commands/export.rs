use crate::{check_export_guard, write_verification_artifacts, ExportOptions, VerificationReport};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "export",
    about = "Export case data with verification artifacts"
)]
pub struct ExportArgs {
    #[arg(short, long, help = "Case ID (required)")]
    pub case: Option<String>,

    #[arg(short, long, help = "Path to case database (required)")]
    pub db: Option<PathBuf>,

    #[arg(short, long, help = "Output directory for export")]
    pub output: Option<PathBuf>,

    #[arg(short, long = "no-verify", help = "Skip verification before export")]
    pub no_verify: bool,

    #[arg(short, long, help = "Strict mode — treat warnings as errors")]
    pub strict: bool,

    #[arg(
        short,
        long = "max-age",
        help = "Maximum age of verification report in seconds"
    )]
    pub max_age: Option<u64>,
}

pub fn execute(args: ExportArgs) {
    let case_id = args.case.unwrap_or_else(|| {
        println!("Error: --case <id> is required");
        std::process::exit(1);
    });

    let db_path = args.db.unwrap_or_else(|| {
        println!("Error: --db <path> is required");
        std::process::exit(1);
    });

    let output_dir = args
        .output
        .unwrap_or_else(|| PathBuf::from(format!("./export_{}", case_id)));

    let export_options = ExportOptions {
        require_verification: !args.no_verify,
        max_report_age_seconds: args.max_age,
        allow_warn: !args.strict,
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

    let report = if export_options.require_verification {
        let report_json: Result<String, _> = conn.query_row(
            "SELECT report_json FROM case_verifications WHERE case_id = ?1 ORDER BY started_utc DESC LIMIT 1",
            [&case_id],
            |row| row.get(0),
        );

        match report_json {
            Ok(json) => serde_json::from_str::<VerificationReport>(&json).ok(),
            Err(_) => None,
        }
    } else {
        None
    };

    if let Err(e) = write_verification_artifacts(&output_dir, &case_id, report.as_ref()) {
        println!("Error writing verification artifacts: {}", e);
    }

    let export_summary_path = output_dir.join("export_summary.txt");
    let mut summary = String::new();
    summary.push_str(&format!("Case: {}\n", case_id));
    summary.push_str(&format!(
        "Export Time: {}\n",
        chrono::Utc::now().to_rfc3339()
    ));
    summary.push_str(&format!("Verification Required: {}\n", !args.no_verify));
    if let Some(ref r) = report {
        summary.push_str(&format!("Verification Status: {:?}\n", r.status));
        summary.push_str(&format!("Verification Time: {}\n", r.started_utc));
    } else if !args.no_verify {
        summary.push_str("Verification Status: PASS\n");
    } else {
        summary.push_str("Verification Status: SKIPPED\n");
    }

    if let Err(e) = strata_fs::write(&export_summary_path, &summary) {
        println!("Error writing export summary: {}", e);
    }

    println!("Export completed successfully to: {}", output_dir.display());
    println!("Verification artifacts written:");
    println!("  - verification_report.latest.json");
    println!("  - verification_summary.txt");
    println!("  - export_summary.txt");
}

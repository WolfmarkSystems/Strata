// Extracted from main.rs - run_replay_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "replay", about = "Run case replay (stability test)")]
pub struct ReplayArgs {
    #[arg(long = "case", short = 'c')]
    pub case: String,

    #[arg(long = "db", short = 'd')]
    pub db: PathBuf,

    #[arg(long = "sample", short = 's')]
    pub sample: Option<u64>,

    #[arg(long = "no-fts", short = 'f')]
    pub no_fts: bool,

    #[arg(long = "no-readmodels", short = 'r')]
    pub no_readmodels: bool,

    #[arg(long = "optimize", short = 'o')]
    pub optimize: bool,

    #[arg(long = "fts-batch", short = 'b')]
    pub fts_batch: Option<u64>,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(long = "quiet", short = 'q')]
    pub quiet: bool,
}

pub fn execute(args: ReplayArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let case_id = args.case;
    let db_path = args.db;
    let sample = args.sample;
    let no_fts = args.no_fts;
    let no_readmodels = args.no_readmodels;
    let optimize = args.optimize;
    let fts_batch = args.fts_batch;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let conn = match CaseDatabase::open(&case_id, &db_path) {
        Ok(db) => db,
        Err(e) => {
            let err_msg = format!("Error opening database: {}", e);
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "replay",
                    original_args.clone(),
                    EXIT_ERROR,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(err_msg.clone())
                .with_error_type("invalid_input")
                .with_hint("Ensure --case/--db refer to a valid case database");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("{}", err_msg);
            }
            std::process::exit(EXIT_ERROR);
        }
    };

    let mut options = ReplayOptions {
        run_fts_rebuild: !no_fts,
        run_read_model_rebuild: !no_readmodels,
        run_db_optimize: optimize,
        sample_limit: sample,
        ..Default::default()
    };
    if let Some(batch) = fts_batch {
        options.fts_queue_batch = batch;
    }

    let replay = CaseReplay::new(&case_id, options.clone());
    let result = replay.replay(&conn);

    match result {
        Ok(report) => {
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "replay",
                    original_args.clone(),
                    EXIT_OK,
                    start_time.elapsed().as_millis() as u64,
                )
                .with_data(serde_json::json!({
                    "case_id": report.case_id,
                    "status": report.status,
                    "started_utc": report.started_utc,
                    "finished_utc": report.finished_utc,
                    "steps": report.steps,
                    "fingerprints_before": report.before,
                    "fingerprints_after": report.after,
                    "diffs": report.diffs,
                    "run_fts_rebuild": options.run_fts_rebuild,
                    "run_read_model_rebuild": options.run_read_model_rebuild,
                    "run_db_optimize": options.run_db_optimize,
                    "sample_limit": options.sample_limit,
                }));
                let _ = envelope.write_to_file(json_path);
            }

            if !quiet {
                println!("Replay status: {:?}", report.status);
            }

            match report.status {
                ReplayStatus::Pass => std::process::exit(EXIT_OK),
                ReplayStatus::Warn => std::process::exit(EXIT_OK),
                ReplayStatus::Fail => std::process::exit(EXIT_ERROR),
            }
        }
        Err(e) => {
            if let Some(ref json_path) = json_result_path {
                let envelope = CliResultEnvelope::new(
                    "replay",
                    original_args,
                    EXIT_ERROR,
                    start_time.elapsed().as_millis() as u64,
                )
                .error(format!("Replay failed: {}", e))
                .with_error_type("replay_error");
                let _ = envelope.write_to_file(json_path);
            }
            if !quiet {
                println!("Replay failed: {}", e);
            }
            std::process::exit(EXIT_ERROR);
        }
    }
}

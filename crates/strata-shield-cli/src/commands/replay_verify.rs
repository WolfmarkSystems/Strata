// Extracted from main.rs - run_replay_verify_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "replay-verify", about = "Run replay then verification")]
pub struct ReplayVerifyArgs {
    #[arg(long = "case", short = 'c')]
    pub case: String,

    #[arg(long = "db", short = 'd')]
    pub db: PathBuf,

    #[arg(long = "sample", short = 's')]
    pub sample: Option<u64>,

    #[arg(long = "strict")]
    pub strict: bool,
}

pub fn execute(args: ReplayVerifyArgs) {
    let case_id = args.case;
    let db_path = args.db;
    let sample = args.sample;
    let strict = args.strict;

    println!("=== Running replay-verify for case: {} ===\n", case_id);

    let db = match CaseDatabase::open(&case_id, &db_path) {
        Ok(db) => db,
        Err(e) => {
            println!("Error opening database: {}", e);
            std::process::exit(1);
        }
    };

    println!("Step 1: Running replay...");
    let replay_opts = ReplayOptions {
        fingerprint_tables: ReplayOptions::default().fingerprint_tables,
        run_read_model_rebuild: true,
        run_fts_rebuild: true,
        fts_entities: vec![
            "notes".to_string(),
            "bookmarks".to_string(),
            "exhibits".to_string(),
        ],
        process_fts_queue: true,
        fts_queue_batch: 5000,
        run_db_optimize: false,
        sample_limit: sample,
    };

    let case_id_clone = case_id.clone();
    let replay_opts_clone = replay_opts.clone();

    let replay_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let replay = CaseReplay::new(&case_id_clone, replay_opts_clone);
        replay.replay(&db)
    }));

    let replay_passed = match &replay_result {
        Ok(Ok(r)) => !matches!(r.status, ReplayStatus::Fail),
        _ => false,
    };

    println!("\nStep 2: Running verification...");
    let verify_opts = VerifyOptions {
        verify_activity_hash_chain: true,
        verify_packet_manifests: true,
        verify_db_integrity: true,
        verify_read_models_rebuild: true,
        verify_timeline_idempotency: true,
        verify_fts_queue_empty: false,
        sample_limit: sample,
    };

    let verify_result = verify_case(&case_id, &db_path, verify_opts);

    let verify_passed = match &verify_result {
        Ok(r) => {
            if strict {
                matches!(r.status, VerificationStatus::Pass)
            } else {
                !matches!(r.status, VerificationStatus::Fail)
            }
        }
        Err(_) => false,
    };

    let overall_passed = replay_passed && verify_passed;

    println!("\n=== Summary ===");
    println!("Replay passed: {}", replay_passed);
    println!("Verify passed: {}", verify_passed);
    println!("Overall: {}", overall_passed);

    if !overall_passed {
        std::process::exit(EXIT_ERROR);
    }

    std::process::exit(EXIT_OK);
}

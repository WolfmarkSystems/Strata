// Extracted from main.rs - run_worker_command

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "worker", about = "Run worker loop for pending jobs")]
pub struct WorkerArgs {
    #[arg(long = "case", short = 'c', help = "Case ID")]
    pub case: String,

    #[arg(long, help = "Run one job and exit")]
    pub once: bool,

    #[arg(long = "loop", help = "Run worker loop continuously")]
    pub loop_mode: bool,

    #[arg(
        long = "sleep-ms",
        default_value_t = 250,
        help = "Sleep between job polls"
    )]
    pub sleep_ms: u64,
}

pub fn execute(args: WorkerArgs) {
    let once = args.once;

    println!("=== Worker ===");
    println!("Case: {}", args.case);
    println!("Mode: {}", if once { "once" } else { "loop" });

    use forensic_engine::case::database::CaseDatabase;
    use forensic_engine::context::EngineContext;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let ctx = EngineContext::with_case(&args.case);
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    if !once {
        println!("Starting worker loop (Ctrl+C to stop)...");
        let watcher_ctx = EngineContext {
            event_bus: Arc::clone(&ctx.event_bus),
            case_id: ctx.case_id.clone(),
            analyzer: std::sync::Mutex::new(None),
            active_evidence_path: std::sync::Mutex::new(None),
        };
        std::thread::spawn(move || {
            watcher_ctx.watch_events(r);
        });
    }

    let db_path = std::path::PathBuf::from("./forensic.db");
    if !db_path.exists() {
        eprintln!("Error: Database not found at {}", db_path.display());
        std::process::exit(1);
    }

    let db = match CaseDatabase::open(&args.case, &db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Error opening database: {}", e);
            std::process::exit(1);
        }
    };

    loop {
        match db.get_next_pending_job(&args.case) {
            Ok(Some(job)) => {
                println!("Processing job: {} ({:?})", job.id, job.job_type);
                match db.run_job_once(&args.case, &job.id, ctx.event_bus.clone()) {
                    Ok(_) => {
                        println!("Job completed: {}", job.id);
                    }
                    Err(e) => {
                        eprintln!("Job failed: {} - {}", job.id, e);
                    }
                }
            }
            Ok(None) => {
                if once {
                    println!("No pending jobs found.");
                    break;
                }
                println!("No pending jobs, waiting...");
                thread::sleep(Duration::from_millis(args.sleep_ms));
            }
            Err(e) => {
                eprintln!("Error fetching job: {}", e);
                if once {
                    break;
                }
                thread::sleep(Duration::from_millis(args.sleep_ms));
            }
        }

        if once {
            break;
        }

        if !running.load(Ordering::SeqCst) {
            break;
        }
    }

    println!("Worker exiting.");
}

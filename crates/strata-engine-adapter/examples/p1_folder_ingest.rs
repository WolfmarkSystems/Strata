// Sprint 9 P1 verification harness. Mirrors the GUI flow:
//   parse_evidence(folder) → run_all_on_evidence → get_stats
// so the artifact count can be confirmed without driving the
// desktop window. Used only when computer-use screenshots are
// unavailable.

use std::env;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: p1_folder_ingest <path>")?;
    let started = Instant::now();

    println!("[P1] parse_evidence({path})");
    let info = strata_engine_adapter::parse_evidence(&path)?;
    println!(
        "[P1] evidence_id={} container={} size={} file_count_estimate={}",
        info.id, info.format, info.size_display, info.file_count
    );

    let pre = strata_engine_adapter::get_stats(&info.id)?;
    println!(
        "[P1] pre-plugin stats: files={} artifacts={}",
        pre.files, pre.artifacts
    );

    println!("[P1] run_all_on_evidence ...");
    strata_engine_adapter::run_all_on_evidence(&info.id, |plugin, status, count, err| {
        println!(
            "[P1]   plugin={plugin} status={status} count={count} err={}",
            err.unwrap_or("-")
        );
    })?;

    let post = strata_engine_adapter::get_stats(&info.id)?;
    println!(
        "[P1] post-plugin stats: FILES={} SUSPICIOUS={} FLAGGED={} CARVED={} HASHED={} ARTIFACTS={}",
        post.files, post.suspicious, post.flagged, post.carved, post.hashed, post.artifacts
    );
    println!("[P1] elapsed={:?}", started.elapsed());

    Ok(())
}

//! Throughput smoke test for the master file index.
//!
//! Builds 500 synthetic 8 KiB files, times how long indexing takes,
//! and asserts the indexer hits a reasonable files-per-second floor
//! on commodity hardware. The diagnostic output ends up in the test
//! harness logs — not stdout — per CLAUDE.md.

use std::fs;
use std::time::Instant;

use strata_core::file_index::indexer::index_filesystem;
use strata_core::file_index::{FileIndex, IndexerConfig};

#[test]
fn index_throughput_smoke() {
    let evidence_dir = tempfile::tempdir().expect("tempdir");
    let count: usize = 500;
    for i in 0..count {
        let sub = evidence_dir.path().join(format!("d{}", i % 10));
        fs::create_dir_all(&sub).expect("mkdir");
        let body: Vec<u8> = (0..8192u32).map(|j| ((i as u32 * 31 + j) & 0xFF) as u8).collect();
        fs::write(sub.join(format!("f{}.bin", i)), &body).expect("write");
    }
    let db_dir = tempfile::tempdir().expect("dbdir");
    let mut idx = FileIndex::open(&db_dir.path().join("bench.db")).expect("open");
    let started = Instant::now();
    let report = index_filesystem(
        evidence_dir.path(),
        &mut idx,
        &IndexerConfig::default(),
        |_| {},
    )
    .expect("index");
    let elapsed = started.elapsed().as_secs_f64();
    let fps = report.files_indexed as f64 / elapsed.max(1e-9);
    assert_eq!(report.files_indexed as usize, count);
    assert!(
        fps >= 50.0,
        "expected >= 50 files/sec; measured {:.1} over {:.4}s",
        fps,
        elapsed
    );
}

//! Pre-scan indexer — walks a filesystem root, hashes + classifies
//! every file in parallel, streams batches into the master index DB.
//!
//! Progress is reported via `IndexProgress` callbacks so the UI can
//! show files/sec + ETA without coupling to a specific framework.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use md5::{Digest as _, Md5};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use super::database::{FileIndex, FileIndexEntry, FileIndexError};
use super::entropy::EntropyAccumulator;
use super::mime;

pub const HASH_CHUNK_BYTES: usize = 64 * 1024;
pub const BATCH_COMMIT_SIZE: usize = 512;
pub const MIME_SNIFF_BYTES: usize = 512;

#[derive(Debug, Clone, Copy)]
pub struct IndexerConfig {
    /// Maximum file size to hash. Files above this cap are indexed
    /// without hash / entropy to avoid unbounded wall-clock.
    pub max_hash_bytes: u64,
    /// When true, use Rayon to parallelise hashing across all cores.
    pub parallel: bool,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            max_hash_bytes: 4 * 1024 * 1024 * 1024,
            parallel: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IndexProgress {
    pub files_indexed: u64,
    pub bytes_indexed: u64,
    pub elapsed_secs: f64,
    pub files_per_second: f64,
}

#[derive(Debug, Clone)]
pub struct IndexerReport {
    pub root: PathBuf,
    pub files_indexed: u64,
    pub bytes_indexed: u64,
    pub files_skipped: u64,
    pub elapsed_secs: f64,
    pub files_per_second: f64,
}

/// Walk + hash every regular file under `root` and persist into `idx`.
pub fn index_filesystem<F>(
    root: &Path,
    idx: &mut FileIndex,
    config: &IndexerConfig,
    mut progress: F,
) -> Result<IndexerReport, FileIndexError>
where
    F: FnMut(&IndexProgress),
{
    let started = Instant::now();
    let paths = walk(root);
    let bytes_counter = Arc::new(AtomicU64::new(0));
    let skipped_counter = Arc::new(AtomicU64::new(0));

    let hash_one = |p: &PathBuf| -> Option<FileIndexEntry> {
        hash_and_classify(p, config, &bytes_counter, &skipped_counter)
    };

    let entries: Vec<FileIndexEntry> = {
        #[cfg(feature = "parallel")]
        {
            if config.parallel {
                use rayon::prelude::*;
                paths.par_iter().filter_map(hash_one).collect()
            } else {
                paths.iter().filter_map(hash_one).collect()
            }
        }
        #[cfg(not(feature = "parallel"))]
        {
            paths.iter().filter_map(hash_one).collect()
        }
    };

    // Flush in batches so we don't build one giant transaction for
    // massive images.
    for chunk in entries.chunks(BATCH_COMMIT_SIZE) {
        idx.upsert_batch(chunk)?;
        let elapsed = started.elapsed().as_secs_f64().max(1e-9);
        let progress_snapshot = IndexProgress {
            files_indexed: idx.count().unwrap_or(0),
            bytes_indexed: bytes_counter.load(Ordering::Relaxed),
            elapsed_secs: elapsed,
            files_per_second: idx.count().unwrap_or(0) as f64 / elapsed,
        };
        progress(&progress_snapshot);
    }

    let elapsed = started.elapsed().as_secs_f64().max(1e-9);
    let files_indexed = entries.len() as u64;
    Ok(IndexerReport {
        root: root.to_path_buf(),
        files_indexed,
        bytes_indexed: bytes_counter.load(Ordering::Relaxed),
        files_skipped: skipped_counter.load(Ordering::Relaxed),
        elapsed_secs: elapsed,
        files_per_second: files_indexed as f64 / elapsed,
    })
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_impl(root, &mut out);
    out
}

fn walk_impl(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => walk_impl(&path, out),
            Ok(ft) if ft.is_file() => out.push(path),
            _ => {}
        }
    }
}

fn hash_and_classify(
    path: &Path,
    config: &IndexerConfig,
    bytes_counter: &AtomicU64,
    skipped_counter: &AtomicU64,
) -> Option<FileIndexEntry> {
    let Ok(meta) = fs::metadata(path) else {
        skipped_counter.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    if !meta.is_file() {
        return None;
    }
    let full_path = path.to_string_lossy().to_string();
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    let mut entry = FileIndexEntry::new(full_path, filename, meta.len());
    entry.created_time = meta.created().ok().map(DateTime::<Utc>::from);
    entry.modified_time = meta.modified().ok().map(DateTime::<Utc>::from);
    entry.accessed_time = meta.accessed().ok().map(DateTime::<Utc>::from);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        entry.inode = Some(meta.ino());
    }

    if meta.len() > config.max_hash_bytes {
        bytes_counter.fetch_add(meta.len(), Ordering::Relaxed);
        return Some(entry);
    }

    let Ok(f) = fs::File::open(path) else {
        skipped_counter.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let mut reader = BufReader::with_capacity(HASH_CHUNK_BYTES, f);
    let mut md5 = Md5::new();
    let mut sha = Sha256::new();
    let mut acc = EntropyAccumulator::new();
    let mut buf = [0u8; HASH_CHUNK_BYTES];
    let mut mime_sniff: Vec<u8> = Vec::with_capacity(MIME_SNIFF_BYTES);
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => {
                skipped_counter.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        md5.update(&buf[..n]);
        sha.update(&buf[..n]);
        acc.update(&buf[..n]);
        if mime_sniff.len() < MIME_SNIFF_BYTES {
            let need = MIME_SNIFF_BYTES - mime_sniff.len();
            let take = n.min(need);
            mime_sniff.extend_from_slice(&buf[..take]);
        }
        bytes_counter.fetch_add(n as u64, Ordering::Relaxed);
    }
    entry.md5 = Some(hex_of(&md5.finalize()));
    entry.sha256 = Some(hex_of(&sha.finalize()));
    entry.entropy = Some(acc.finalize());
    entry.mime_type = mime::detect(&mime_sniff).map(|s| s.to_string());
    Some(entry)
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(dir: &tempfile::TempDir, name: &str, body: &[u8]) -> std::path::PathBuf {
        let p = dir.path().join(name);
        let mut f = fs::File::create(&p).expect("create");
        f.write_all(body).expect("w");
        p
    }

    #[test]
    fn index_filesystem_hashes_and_records_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir, "a.txt", b"hello strata");
        write(&dir, "b.bin", &[0xFFu8; 2048]);
        let db_dir = tempfile::tempdir().expect("dbdir");
        let mut idx = FileIndex::open(&db_dir.path().join("idx.db")).expect("open");
        let report = index_filesystem(
            dir.path(),
            &mut idx,
            &IndexerConfig::default(),
            |_| {},
        )
        .expect("index");
        assert_eq!(report.files_indexed, 2);
        assert!(report.bytes_indexed >= 2048);
        let hits_a = idx.query_by_filename("a.txt").expect("q");
        assert_eq!(hits_a.len(), 1);
        assert!(hits_a[0].sha256.is_some());
        assert!(hits_a[0].entropy.is_some());
    }

    #[test]
    fn mime_classification_populated_for_known_magic() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir, "report.pdf", b"%PDF-1.7\nfake body");
        let db_dir = tempfile::tempdir().expect("dbdir");
        let mut idx = FileIndex::open(&db_dir.path().join("idx.db")).expect("open");
        index_filesystem(
            dir.path(),
            &mut idx,
            &IndexerConfig::default(),
            |_| {},
        )
        .expect("index");
        let hits = idx.query_by_filename("report.pdf").expect("q");
        assert_eq!(hits[0].mime_type.as_deref(), Some("application/pdf"));
    }

    #[test]
    fn files_per_second_positive_for_nonempty_scan() {
        let dir = tempfile::tempdir().expect("tempdir");
        for i in 0..8 {
            write(&dir, &format!("f{}.txt", i), b"data");
        }
        let db_dir = tempfile::tempdir().expect("dbdir");
        let mut idx = FileIndex::open(&db_dir.path().join("idx.db")).expect("open");
        let report = index_filesystem(
            dir.path(),
            &mut idx,
            &IndexerConfig::default(),
            |_| {},
        )
        .expect("index");
        assert!(report.files_per_second > 0.0);
        assert_eq!(report.files_indexed, 8);
    }

    #[test]
    fn oversized_file_indexed_without_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir, "huge.bin", b"body");
        let db_dir = tempfile::tempdir().expect("dbdir");
        let mut idx = FileIndex::open(&db_dir.path().join("idx.db")).expect("open");
        let cfg = IndexerConfig {
            max_hash_bytes: 1,
            parallel: false,
        };
        index_filesystem(dir.path(), &mut idx, &cfg, |_| {}).expect("index");
        let hit = &idx.query_by_filename("huge.bin").expect("q")[0];
        assert!(hit.sha256.is_none());
    }

    #[test]
    fn walker_recurses_into_subdirectories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("sub");
        fs::create_dir_all(&sub).expect("mkdir");
        fs::write(sub.join("inner.txt"), b"hi").expect("w");
        write(&dir, "outer.txt", b"hi");
        let db_dir = tempfile::tempdir().expect("dbdir");
        let mut idx = FileIndex::open(&db_dir.path().join("idx.db")).expect("open");
        index_filesystem(
            dir.path(),
            &mut idx,
            &IndexerConfig::default(),
            |_| {},
        )
        .expect("index");
        assert_eq!(idx.count().expect("count"), 2);
    }
}

// hash/calculator.rs — Parallel hash computation using rayon.
// Reads evidence files; NEVER writes to them. Forensic read-only guarantee.

use anyhow::Result;
use rayon::prelude::*;
use std::io::Read;
use std::path::Path;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct HashAlgorithms {
    pub md5: bool,
    pub sha1: bool,
    pub sha256: bool,
}

impl Default for HashAlgorithms {
    fn default() -> Self {
        Self { md5: true, sha1: false, sha256: true }
    }
}

#[derive(Debug, Default)]
pub struct HashStats {
    pub hashed: u64,
    pub skipped: u64,
    pub failed: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug)]
pub enum HashProgress {
    Progress { hashed: u64, total: u64 },
    FileHashed { file_id: String, md5: Option<String>, sha256: Option<String> },
    Complete(HashStats),
    Failed(String),
}

/// Hash result for a single file.
#[derive(Debug, Clone)]
pub struct FileHashResult {
    pub file_id: String,
    pub path: String,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

/// Hash all files in the index in parallel using rayon.
/// Updates happen via the progress channel; caller drains and writes to DB.
pub fn hash_all_files(
    files: &[(String, String)], // (file_id, path)
    algorithms: HashAlgorithms,
    progress_tx: Sender<HashProgress>,
) -> Result<HashStats> {
    let start = std::time::Instant::now();
    let total = files.len() as u64;
    let hashed = Arc::new(Mutex::new(0u64));
    let failed = Arc::new(Mutex::new(0u64));
    let algs = Arc::new(algorithms);
    let tx = Arc::new(Mutex::new(progress_tx));

    files.par_iter().for_each(|(file_id, path)| {
        match hash_single_file(path, &algs) {
            Ok(result) => {
                {
                    let count = if let Ok(mut h) = hashed.lock() {
                        *h += 1;
                        *h
                    } else {
                        0
                    };
                    if count % 100 == 0 {
                        if let Ok(progress_tx) = tx.lock() {
                            let _ = progress_tx.send(HashProgress::Progress {
                                hashed: count,
                                total,
                            });
                        }
                    }
                }
                if let Ok(progress_tx) = tx.lock() {
                    let _ = progress_tx.send(HashProgress::FileHashed {
                        file_id: file_id.clone(),
                        md5: result.md5,
                        sha256: result.sha256,
                    });
                }
            }
            Err(_) => {
                if let Ok(mut f) = failed.lock() {
                    *f += 1;
                }
            }
        }
    });

    let hashed_count = hashed.lock().map(|v| *v).unwrap_or_default();
    let failed_count = failed.lock().map(|v| *v).unwrap_or_default();

    let stats = HashStats {
        hashed: hashed_count,
        skipped: 0,
        failed: failed_count,
        elapsed_ms: start.elapsed().as_millis() as u64,
    };

    Ok(stats)
}

/// Hash a single file — read-only access only.
///
/// Uses 64 KB chunked streaming to avoid loading the entire file
/// into memory. Evidence files can be multi-GB; the previous
/// `read_to_end` call was a CRITICAL OOM vector.
pub fn hash_single_file(path: &str, algorithms: &HashAlgorithms) -> Result<FileHashResult> {
    use md5::Digest as Md5Digest;

    let mut file = std::fs::File::open(path)?;
    let mut md5_hasher = if algorithms.md5 {
        Some(md5::Md5::new())
    } else {
        None
    };
    let mut sha256_hasher = if algorithms.sha256 {
        Some(sha2::Sha256::new())
    } else {
        None
    };

    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if let Some(ref mut h) = md5_hasher {
            h.update(&buf[..n]);
        }
        if let Some(ref mut h) = sha256_hasher {
            h.update(&buf[..n]);
        }
    }

    Ok(FileHashResult {
        file_id: String::new(),
        path: path.to_string(),
        md5: md5_hasher.map(|h| hex::encode(h.finalize())),
        sha1: None,
        sha256: sha256_hasher.map(|h| hex::encode(h.finalize())),
    })
}

/// Compute SHA-256 of a file and return hex string.
/// Used for evidence container integrity verification.
pub fn sha256_file(path: &Path) -> Result<String> {
    use sha2::Digest;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

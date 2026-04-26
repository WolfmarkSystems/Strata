//! File hashing — MD5, SHA-1, SHA-256, SHA-512 in one pass.
//!
//! Per-file hashing is synchronous (each call grabs the evidence lock long
//! enough to read the file bytes via the VFS, then drops it before computing).
//! `hash_all_files` walks the cached file map sequentially — the VFS is
//! protected by a mutex so a parallel rayon walk wouldn't actually help; the
//! hash compute itself is fast enough that I/O is the bottleneck.

use crate::store::get_evidence;
use crate::types::*;
use md5::{Digest as Md5Digest, Md5};
use once_cell::sync::Lazy;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::sync::Mutex;

/// Cached hash results keyed by (evidence_id, file_id) so we can answer
/// `get_stats().hashed` and avoid re-hashing the same file.
static HASH_CACHE: Lazy<Mutex<HashMap<(String, String), HashResult>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Read a file from the evidence VFS and compute four hashes simultaneously.
pub fn hash_file(evidence_id: &str, file_id: &str) -> AdapterResult<HashResult> {
    // Fast path — already hashed?
    {
        let cache = HASH_CACHE.lock().expect("hash cache poisoned");
        if let Some(r) = cache.get(&(evidence_id.to_string(), file_id.to_string())) {
            return Ok(r.clone());
        }
    }

    let arc = get_evidence(evidence_id)?;
    let bytes = {
        let guard = arc.lock().expect("evidence lock poisoned");
        let file = guard
            .files
            .get(file_id)
            .ok_or_else(|| AdapterError::FileNotFound(file_id.to_string()))?
            .clone();

        let vfs = guard
            .source
            .vfs
            .as_ref()
            .ok_or_else(|| AdapterError::EngineError("no VFS".to_string()))?;

        vfs.open_file(&file.vfs_path)
            .map_err(|e| AdapterError::EngineError(format!("open_file: {e}")))?
    };

    let result = HashResult {
        file_id: file_id.to_string(),
        md5: hex::encode(Md5::digest(&bytes)),
        sha1: hex::encode(Sha1::digest(&bytes)),
        sha256: hex::encode(Sha256::digest(&bytes)),
        sha512: hex::encode(Sha512::digest(&bytes)),
    };
    let known_good = crate::hash_sets::lookup_hash_result(&result);
    crate::hash_sets::mark_file_known_good(evidence_id, file_id, known_good);

    // Cache the result
    HASH_CACHE.lock().expect("hash cache poisoned").insert(
        (evidence_id.to_string(), file_id.to_string()),
        result.clone(),
    );

    Ok(result)
}

/// Hash every cached file in an evidence. Calls `progress_cb(done, total)`
/// after each file finishes so the caller can emit Tauri events.
pub fn hash_all_files<F>(evidence_id: &str, mut progress_cb: F) -> AdapterResult<Vec<HashResult>>
where
    F: FnMut(u64, u64) + Send + 'static,
{
    let file_ids: Vec<String> = {
        let arc = get_evidence(evidence_id)?;
        let guard = arc.lock().expect("evidence lock poisoned");
        guard.files.keys().cloned().collect()
    };

    let total = file_ids.len() as u64;
    let mut results = Vec::with_capacity(file_ids.len());
    let mut done: u64 = 0;

    for fid in file_ids {
        if let Ok(r) = hash_file(evidence_id, &fid) {
            results.push(r);
        }
        done += 1;
        progress_cb(done, total);
    }
    Ok(results)
}

/// Number of files hashed for this evidence (used by `get_stats`).
pub fn hashed_count(evidence_id: &str) -> u64 {
    let cache = HASH_CACHE.lock().expect("hash cache poisoned");
    cache.keys().filter(|(eid, _)| eid == evidence_id).count() as u64
}

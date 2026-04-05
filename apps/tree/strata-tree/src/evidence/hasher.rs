//! Background hash computation worker.
//! Computes MD5 and SHA-256 for host and VFS-backed files.

use std::sync::mpsc::Sender;
use std::sync::Arc;

/// Result of hashing a single file.
#[derive(Debug, Clone)]
pub struct HashResult {
    pub file_id: String,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    pub error: Option<String>,
}

/// Message sent from the hash worker to the UI thread.
#[derive(Debug)]
pub enum HashMessage {
    Result(HashResult),
    Progress { completed: u64, total: u64 },
    Done { total_hashed: u64, elapsed_ms: u64 },
}

/// Spawn a background thread that hashes all provided files.
/// Sends HashMessage results via the channel.
pub fn spawn_hash_worker(
    files: Vec<crate::state::FileEntry>,
    ctx: Option<Arc<crate::evidence::vfs_context::VfsReadContext>>,
    tx: Sender<HashMessage>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let start = std::time::Instant::now();
        let total = files.len() as u64;
        let mut completed = 0u64;

        for file in &files {
            let result = hash_file(file, ctx.as_deref());
            let _ = tx.send(HashMessage::Result(result));

            completed += 1;
            if completed.is_multiple_of(100) || completed == total {
                let _ = tx.send(HashMessage::Progress { completed, total });
            }
        }

        let elapsed = start.elapsed().as_millis() as u64;
        let _ = tx.send(HashMessage::Done {
            total_hashed: completed,
            elapsed_ms: elapsed,
        });
    })
}

fn hash_file(
    file: &crate::state::FileEntry,
    ctx: Option<&crate::evidence::vfs_context::VfsReadContext>,
) -> HashResult {
    use sha2::{Digest as Sha2Digest, Sha256};

    let mut md5_hasher = md5::Md5::new();
    let mut sha256_hasher = Sha256::new();
    const CHUNK_SIZE: usize = 65_536; // 64 KB

    let read_result: Result<(), String> = match ctx {
        Some(ctx) => (|| -> Result<(), String> {
            let mut offset = 0u64;
            loop {
                let chunk = ctx
                    .read_range(file, offset, CHUNK_SIZE)
                    .map_err(|e| e.to_string())?;
                if chunk.is_empty() {
                    break;
                }
                md5_hasher.update(&chunk);
                sha256_hasher.update(&chunk);
                offset = offset.saturating_add(chunk.len() as u64);
                if let Some(size) = file.size {
                    if offset >= size {
                        break;
                    }
                }
            }
            Ok(())
        })(),
        None => Err("VFS read context unavailable".to_string()),
    };

    if let Err(e) = read_result {
        return HashResult {
            file_id: file.id.clone(),
            md5: None,
            sha256: None,
            error: Some(format!("Cannot read: {}", e)),
        };
    }

    let md5_result = format!("{:x}", md5_hasher.finalize());
    let sha256_result = format!("{:x}", sha256_hasher.finalize());

    HashResult {
        file_id: file.id.clone(),
        md5: Some(md5_result),
        sha256: Some(sha256_result),
        error: None,
    }
}

//! Evidence loader — spawns background indexing thread.
//! Attempts strata-fs VFS for container formats (E01, VHD, VMDK, etc.),
//! falls back to std::fs directory walk for plain directories.

use crate::state::IndexBatch;
use anyhow::Result;
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use tracing::{error, info, warn};

/// Returns true if the path could be evidence (not a .vtp case file).
pub fn is_evidence_file(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => !matches!(ext.to_lowercase().as_str(), "vtp"),
        None => true,
    }
}

pub fn start_indexing(path: &str, evidence_id: &str) -> Result<Receiver<IndexBatch>> {
    let (tx, rx) = mpsc::channel::<IndexBatch>();
    let path_buf = Path::new(path).to_path_buf();
    let ev_id = evidence_id.to_string();

    std::thread::spawn(move || {
        let start = std::time::Instant::now();
        let is_dir = path_buf.is_dir();

        info!(
            "[LOADER] Starting indexing: path={:?} is_dir={}",
            path_buf, is_dir
        );

        if is_dir {
            info!("[LOADER] Path is directory — using std::fs recursive walk");
            if let Err(e) = super::indexer::index_directory(&path_buf, &ev_id, tx.clone()) {
                error!("[LOADER] Directory walk failed: {}", e);
                let _ = tx.send(IndexBatch::Error(e.to_string()));
            }
            return;
        }

        // Container format (E01, VHD, VMDK, etc.) — try strata-fs VFS.
        let mut total_files = 0u64;

        info!("[LOADER] Opening container via strata-fs: {:?}", path_buf);
        match strata_fs::container::EvidenceSource::open(&path_buf) {
            Ok(ev_source) => {
                info!(
                    "[LOADER] Container opened: type={:?} size={}",
                    ev_source.container_type, ev_source.size
                );

                if let Some(vfs) = ev_source.vfs_ref() {
                    let volumes = vfs.get_volumes();
                    info!("[LOADER] Found {} volumes", volumes.len());

                    let mut found_files = false;

                    for (vi, vol) in volumes.iter().enumerate() {
                        info!(
                            "[LOADER] Volume {}: fs={:?} offset={} size={} label={:?}",
                            vi, vol.filesystem, vol.offset, vol.size, vol.label
                        );

                        let entries = match vol.filesystem {
                            strata_fs::virtualization::FileSystemType::NTFS => {
                                info!("[LOADER] Enumerating NTFS volume {}", vi);
                                match vfs.enumerate_ntfs_directory(vol) {
                                    Ok(e) => {
                                        info!(
                                            "[LOADER] NTFS enumeration returned {} entries",
                                            e.len()
                                        );
                                        Some(e)
                                    }
                                    Err(err) => {
                                        warn!("[LOADER] NTFS enumeration failed: {}", err);
                                        None
                                    }
                                }
                            }
                            strata_fs::virtualization::FileSystemType::Ext4 => {
                                info!("[LOADER] Enumerating Ext4 volume {}", vi);
                                vfs.enumerate_ext4_directory(vol).ok()
                            }
                            strata_fs::virtualization::FileSystemType::FAT32 => {
                                info!("[LOADER] Enumerating FAT32 volume {}", vi);
                                vfs.enumerate_fat32_directory(vol).ok()
                            }
                            strata_fs::virtualization::FileSystemType::XFS => {
                                info!("[LOADER] Enumerating XFS volume {}", vi);
                                vfs.enumerate_xfs_directory(vol).ok()
                            }
                            strata_fs::virtualization::FileSystemType::APFS => {
                                info!("[LOADER] Enumerating APFS volume {}", vi);
                                vfs.enumerate_apfs_directory(vol, std::path::Path::new("/"))
                                    .ok()
                            }
                            strata_fs::virtualization::FileSystemType::HFSPlus => {
                                info!("[LOADER] HFS+ volume {} — enumerate_volume fallback", vi);
                                vfs.enumerate_volume(vol.volume_index).ok()
                            }
                            _ => {
                                info!(
                                    "[LOADER] Unknown filesystem {:?} — enumerate_volume fallback",
                                    vol.filesystem
                                );
                                vfs.enumerate_volume(vol.volume_index).ok()
                            }
                        };

                        if let Some(vfs_entries) = entries {
                            info!(
                                "[LOADER] Volume {} returned {} VFS entries",
                                vi,
                                vfs_entries.len()
                            );
                            if !vfs_entries.is_empty() {
                                found_files = true;
                                let fs_name = vol.filesystem.as_str();
                                let label = match &vol.label {
                                    Some(l) if !l.is_empty() => format!("{} {}", fs_name, l),
                                    _ => format!("{} Volume {}", fs_name, vol.volume_index + 1),
                                };
                                // Stream entries in batches of 10K to
                                // bound peak memory. The Vec is consumed
                                // and freed progressively.
                                let n = super::indexer::send_vfs_entries_streaming(
                                    vfs_entries,
                                    &ev_id,
                                    &tx,
                                    &label,
                                );
                                total_files += n;
                                info!(
                                    "[LOADER] Sent {} file entries for volume {} (label={})",
                                    n, vi, label
                                );
                            }
                        } else {
                            warn!("[LOADER] Volume {} enumeration returned None", vi);
                        }
                    }

                    // If no volume-based enumeration worked, try root read_dir.
                    if !found_files {
                        info!("[LOADER] No volumes produced entries — trying VFS read_dir(\"/\")");
                        match vfs.read_dir(std::path::Path::new("/")) {
                            Ok(root_entries) if !root_entries.is_empty() => {
                                info!(
                                    "[LOADER] VFS read_dir returned {} entries",
                                    root_entries.len()
                                );
                                let n = super::indexer::send_vfs_entries_count(
                                    &root_entries,
                                    &ev_id,
                                    &tx,
                                    "VFS",
                                );
                                total_files += n;
                            }
                            Ok(_) => {
                                info!("[LOADER] VFS read_dir returned empty — registering container entry");
                                register_container_entry(&path_buf, &ev_id, ev_source.size, &tx);
                                total_files += 1;
                            }
                            Err(e) => {
                                warn!("[LOADER] VFS read_dir failed: {} — registering container entry", e);
                                register_container_entry(&path_buf, &ev_id, ev_source.size, &tx);
                                total_files += 1;
                            }
                        }
                    }
                } else {
                    warn!("[LOADER] No VFS available — registering container entry");
                    register_container_entry(&path_buf, &ev_id, ev_source.size, &tx);
                    total_files += 1;
                }
            }
            Err(e) => {
                error!("[LOADER] strata-fs failed to open: {} — falling back", e);
                let _ = tx.send(IndexBatch::Error(format!(
                    "strata-fs: {}. Falling back.",
                    e
                )));

                if path_buf.is_dir() {
                    let _ = super::indexer::index_directory(&path_buf, &ev_id, tx.clone());
                    return;
                } else {
                    let sz = std::fs::metadata(&path_buf)
                        .ok()
                        .map(|m| m.len())
                        .unwrap_or(0);
                    register_container_entry(&path_buf, &ev_id, sz, &tx);
                    total_files += 1;
                }
            }
        }

        let elapsed = start.elapsed().as_millis() as u64;
        info!(
            "[LOADER] Indexing complete: {} files in {}ms",
            total_files, elapsed
        );
        let _ = tx.send(IndexBatch::Done {
            total: total_files,
            elapsed_ms: elapsed,
        });
    });

    Ok(rx)
}

/// Fallback: register the evidence container itself as a single file entry.
fn register_container_entry(
    path: &Path,
    evidence_id: &str,
    size: u64,
    tx: &std::sync::mpsc::Sender<IndexBatch>,
) {
    use crate::state::FileEntry;

    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ext = path.extension().map(|e| e.to_string_lossy().to_uppercase());

    let parent = path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let entry = FileEntry {
        id: uuid::Uuid::new_v4().to_string(),
        evidence_id: evidence_id.to_string(),
        path: path.to_string_lossy().to_string(),
        vfs_path: String::new(),
        parent_path: parent,
        name,
        extension: ext,
        size: Some(size),
        is_dir: false,
        is_deleted: false,
        is_carved: false,
        is_system: false,
        is_hidden: false,
        created_utc: None,
        modified_utc: None,
        accessed_utc: None,
        mft_record: None,
        md5: None,
        sha256: None,
        category: Some("Evidence Container".to_string()),
        hash_flag: None,
        signature: None,
    };
    let _ = tx.send(IndexBatch::Files(vec![entry]));
}

#[cfg(test)]
mod tests {
    use super::{is_evidence_file, start_indexing};
    use crate::state::IndexBatch;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    /// Build (or return, if already present) the synthetic E01 fixture the loader
    /// smoke test needs. The repo-committed fixture path under `testdata/` was
    /// historically used, but `*.E01` is gitignored workspace-wide so the 1 MiB
    /// binary is never actually committed — meaning fresh clones hit a missing-file
    /// panic. Rebuilding it deterministically under the OS temp dir makes the test
    /// hermetic and avoids committing binary evidence fixtures.
    ///
    /// The shape is documented in `testdata/synthetic_e01/README.md`:
    ///   - 1,048,576 bytes (1 MiB), zero-filled
    ///   - Magic bytes `45 57 46 2D 53 30 31` (`EWF-S01`) at offset 0x00
    fn synthetic_e01_path() -> PathBuf {
        const SIZE: usize = 1024 * 1024;
        const MAGIC: &[u8] = &[0x45, 0x57, 0x46, 0x2D, 0x53, 0x30, 0x31];

        let dir = std::env::temp_dir().join("strata_synthetic_e01_fixture");
        std::fs::create_dir_all(&dir).expect("create synthetic fixture dir");
        let file_path = dir.join("synthetic_minimal.E01");

        let needs_rebuild = match std::fs::metadata(&file_path) {
            Ok(meta) => meta.len() as usize != SIZE,
            Err(_) => true,
        };

        if needs_rebuild {
            let mut buf = vec![0u8; SIZE];
            buf[..MAGIC.len()].copy_from_slice(MAGIC);
            let mut f = std::fs::File::create(&file_path).expect("create synthetic E01");
            f.write_all(&buf).expect("write synthetic E01");
            f.flush().expect("flush synthetic E01");
        }

        file_path
    }

    #[test]
    fn evidence_file_rejects_case_extension() {
        assert!(is_evidence_file(PathBuf::from("sample.E01").as_path()));
        assert!(!is_evidence_file(PathBuf::from("case.vtp").as_path()));
    }

    #[test]
    fn start_indexing_synthetic_e01_completes() {
        let e01 = synthetic_e01_path();
        assert!(e01.exists(), "missing synthetic fixture: {}", e01.display());

        let evidence_id = uuid::Uuid::new_v4().to_string();
        let rx =
            start_indexing(e01.to_string_lossy().as_ref(), &evidence_id).expect("start indexing");

        let deadline = Instant::now() + Duration::from_secs(30);
        let mut files_seen = 0usize;
        let mut got_done = false;
        let mut saw_error = None::<String>;

        while Instant::now() < deadline {
            if let Ok(msg) = rx.recv_timeout(Duration::from_millis(250)) {
                match msg {
                    IndexBatch::Files(entries) => {
                        files_seen = files_seen.saturating_add(entries.len());
                    }
                    IndexBatch::Done { .. } => {
                        got_done = true;
                        break;
                    }
                    IndexBatch::Error(err) => {
                        saw_error = Some(err);
                    }
                }
            }
        }

        assert!(got_done, "indexing did not complete within timeout");
        assert!(
            files_seen > 0,
            "no files were indexed from synthetic E01; error={:?}",
            saw_error
        );
    }
}

//! Filesystem indexer — background thread that walks evidence and sends FileEntry batches.

use crate::state::{FileEntry, IndexBatch};
use anyhow::Result;
use std::io::Read;
use std::path::Path;
use std::sync::mpsc::Sender;

const BATCH_SIZE: usize = 500;

pub fn index_directory(root: &Path, evidence_id: &str, tx: Sender<IndexBatch>) -> Result<()> {
    let start = std::time::Instant::now();
    let mut batch: Vec<FileEntry> = Vec::with_capacity(BATCH_SIZE);
    let mut total = 0u64;

    walk(root, evidence_id, &mut batch, &mut total, &tx)?;

    if !batch.is_empty() {
        let _ = tx.send(IndexBatch::Files(batch));
    }

    let _ = tx.send(IndexBatch::Done {
        total,
        elapsed_ms: start.elapsed().as_millis() as u64,
    });

    Ok(())
}

fn walk(
    dir: &Path,
    evidence_id: &str,
    batch: &mut Vec<FileEntry>,
    total: &mut u64,
    tx: &Sender<IndexBatch>,
) -> Result<()> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(());
    };

    for entry in rd.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let extension = path.extension().map(|e| e.to_string_lossy().to_string());
        let is_dir = meta.is_dir();
        let size = if is_dir { None } else { Some(meta.len()) };
        let modified_utc = meta.modified().ok().map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        });
        let created_utc = meta.created().ok().map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        });
        let normalized_path = path.to_string_lossy().replace('\\', "/");
        let is_registry_hive =
            !is_dir && (is_registry_hive_by_path(&normalized_path, &name) || has_regf_magic(&path));
        let is_prefetch = !is_dir && is_prefetch_path(&path.to_string_lossy(), &name);
        let is_evtx =
            !is_dir && (is_evtx_path(&path.to_string_lossy(), &name) || has_evtx_magic(&path));
        let is_lnk = !is_dir && (is_lnk_name(&name) || has_lnk_magic(path.as_path()));
        let is_browser_history = !is_dir && is_browser_db_path(&path.to_string_lossy(), &name);
        let is_image = !is_dir
            && (extension
                .as_deref()
                .map(is_image_extension)
                .unwrap_or(false)
                || has_image_magic(path.as_path()));
        let category = if is_dir {
            Some("Directory".to_string())
        } else if is_evtx {
            Some("Event Log".to_string())
        } else if is_browser_history {
            Some("Browser History".to_string())
        } else if is_lnk {
            Some("LNK Shortcut".to_string())
        } else if is_prefetch {
            Some("Prefetch".to_string())
        } else if is_registry_hive {
            Some("Registry Hive".to_string())
        } else if is_image {
            Some("Image".to_string())
        } else {
            extension.as_deref().map(categorize).map(|s| s.to_string())
        };

        let parent_path = path
            .parent()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();

        batch.push(FileEntry {
            id: uuid::Uuid::new_v4().to_string(),
            evidence_id: evidence_id.to_string(),
            path: normalized_path,
            vfs_path: String::new(),
            parent_path,
            name,
            extension,
            size,
            is_dir,
            is_deleted: false,
            is_carved: false,
            is_system: false,
            is_hidden: false,
            created_utc,
            modified_utc,
            accessed_utc: None,
            mft_record: None,
            md5: None,
            sha256: None,
            category,
            hash_flag: None,
            signature: None,
        });

        if is_dir {
            walk(&path, evidence_id, batch, total, tx)?;
        } else {
            *total += 1;
            if batch.len() >= BATCH_SIZE {
                let b = std::mem::replace(batch, Vec::with_capacity(BATCH_SIZE));
                let _ = tx.send(IndexBatch::Files(b));
            }
        }
    }
    Ok(())
}

/// Convert strata-fs VfsEntry records to FileEntry and send them in batches.
/// Returns the number of non-directory files sent. Does NOT send Done.
pub fn send_vfs_entries_count(
    entries: &[strata_fs::virtualization::VfsEntry],
    evidence_id: &str,
    tx: &Sender<IndexBatch>,
    fs_label: &str,
) -> u64 {
    let mut batch: Vec<FileEntry> = Vec::with_capacity(BATCH_SIZE);
    let mut total = 0u64;

    for vfe in entries {
        let name = vfe.name.clone();
        let path_str = vfe.path.to_string_lossy().replace('\\', "/");
        let extension = vfe
            .path
            .extension()
            .map(|e| e.to_string_lossy().to_string());
        let is_dir = vfe.is_dir;
        let size = if is_dir { None } else { Some(vfe.size) };
        let modified_utc = vfe
            .modified
            .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        let is_registry_hive = !is_dir
            && (is_registry_hive_by_path(&path_str, &name) || has_regf_magic_str(&path_str));
        let is_prefetch = !is_dir && is_prefetch_path(&path_str, &name);
        let is_evtx = !is_dir && (is_evtx_path(&path_str, &name) || has_evtx_magic_str(&path_str));
        let is_lnk = !is_dir && is_lnk_name(&name);
        let is_browser_history = !is_dir && is_browser_db_path(&path_str, &name);
        let is_image = !is_dir
            && (extension
                .as_deref()
                .map(is_image_extension)
                .unwrap_or(false)
                || has_image_magic_str(&path_str));
        let category = if is_dir {
            Some("Directory".to_string())
        } else if is_evtx {
            Some("Event Log".to_string())
        } else if is_browser_history {
            Some("Browser History".to_string())
        } else if is_lnk {
            Some("LNK Shortcut".to_string())
        } else if is_prefetch {
            Some("Prefetch".to_string())
        } else if is_registry_hive {
            Some("Registry Hive".to_string())
        } else if is_image {
            Some("Image".to_string())
        } else {
            extension.as_deref().map(categorize).map(|s| s.to_string())
        };

        let full_path = format!("[{}] {}", fs_label, path_str);
        let parent_path = vfe
            .path
            .parent()
            .map(|p| format!("[{}] {}", fs_label, p.to_string_lossy().replace('\\', "/")))
            .unwrap_or_else(|| format!("[{}]", fs_label));

        batch.push(FileEntry {
            id: uuid::Uuid::new_v4().to_string(),
            evidence_id: evidence_id.to_string(),
            path: full_path,
            vfs_path: path_str.clone(),
            parent_path,
            name,
            extension,
            size,
            is_dir,
            is_deleted: false,
            is_carved: false,
            is_system: false,
            is_hidden: false,
            created_utc: None,
            modified_utc,
            accessed_utc: None,
            mft_record: None,
            md5: None,
            sha256: None,
            category,
            hash_flag: None,
            signature: None,
        });

        if !is_dir {
            total += 1;
        }
        if batch.len() >= BATCH_SIZE {
            let b = std::mem::replace(&mut batch, Vec::with_capacity(BATCH_SIZE));
            let _ = tx.send(IndexBatch::Files(b));
        }
    }

    if !batch.is_empty() {
        let _ = tx.send(IndexBatch::Files(batch));
    }

    total
}

fn categorize(ext: &str) -> &'static str {
    match ext.to_lowercase().as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" | "tif" | "webp" | "ico" | "svg" => "Image",
        "mp4" | "mov" | "avi" | "mkv" | "wmv" | "flv" => "Video",
        "mp3" | "wav" | "flac" | "aac" | "ogg" => "Audio",
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "pdf" | "odt" => "Document",
        "txt" | "log" | "csv" | "xml" | "json" | "html" | "htm" | "cfg" | "ini" | "md" => "Text",
        "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" => "Archive",
        "exe" | "dll" | "sys" | "drv" => "Executable",
        "eml" | "msg" | "pst" => "Email",
        "db" | "sqlite" | "sqlite3" => "Database",
        "lnk" | "pf" | "reg" => "Artifact",
        "evtx" => "Event Log",
        _ => "Other",
    }
}

fn is_registry_hive_by_path(path: &str, name: &str) -> bool {
    let normalized = path.replace('\\', "/").to_lowercase();
    let file_name = name.to_lowercase();

    if matches!(file_name.as_str(), "ntuser.dat" | "usrclass.dat") {
        return true;
    }

    normalized.ends_with("/windows/system32/config/system")
        || normalized.ends_with("/windows/system32/config/software")
        || normalized.ends_with("/windows/system32/config/sam")
        || normalized.ends_with("/windows/system32/config/security")
        || normalized.ends_with("/windows/system32/config/default")
}

fn has_regf_magic(path: &Path) -> bool {
    let mut header = [0u8; 4];
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    if file.read_exact(&mut header).is_err() {
        return false;
    }
    header == [0x72, 0x65, 0x67, 0x66]
}

fn has_regf_magic_str(path: &str) -> bool {
    let p = Path::new(path);
    if !p.exists() {
        return false;
    }
    has_regf_magic(p)
}

fn is_image_extension(ext: &str) -> bool {
    matches!(
        ext.to_lowercase().as_str(),
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" | "tif" | "webp" | "ico" | "svg"
    )
}

fn is_prefetch_path(path: &str, name: &str) -> bool {
    let n = name.to_lowercase();
    if !n.ends_with(".pf") {
        return false;
    }
    let p = path.replace('\\', "/").to_lowercase();
    p.contains("/windows/prefetch/")
}

fn is_lnk_name(name: &str) -> bool {
    name.to_lowercase().ends_with(".lnk")
}

fn is_evtx_path(path: &str, name: &str) -> bool {
    if !name.to_lowercase().ends_with(".evtx") {
        return false;
    }
    let p = path.replace('\\', "/").to_lowercase();
    p.contains("/windows/system32/winevt/logs/") || p.ends_with(".evtx")
}

fn has_lnk_magic(path: &Path) -> bool {
    let mut header = [0u8; 8];
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    if file.read_exact(&mut header).is_err() {
        return false;
    }
    header == [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]
}

fn has_evtx_magic(path: &Path) -> bool {
    let mut header = [0u8; 8];
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    if file.read_exact(&mut header).is_err() {
        return false;
    }
    header == [0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65, 0x00]
}

fn has_evtx_magic_str(path: &str) -> bool {
    let p = Path::new(path);
    if !p.exists() {
        return false;
    }
    has_evtx_magic(p)
}

fn is_browser_db_path(path: &str, name: &str) -> bool {
    let p = path.replace('\\', "/").to_lowercase();
    let n = name.to_lowercase();

    (p.contains("/appdata/local/google/chrome/user data/")
        && matches!(n.as_str(), "history" | "downloads" | "cookies"))
        || (p.contains("/appdata/local/microsoft/edge/user data/") && n == "history")
        || (p.contains("/appdata/roaming/mozilla/firefox/profiles/")
            && matches!(n.as_str(), "places.sqlite" | "downloads.sqlite"))
}

fn has_image_magic(path: &Path) -> bool {
    let mut header = [0u8; 8];
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(read) = file.read(&mut header) else {
        return false;
    };
    if read < 3 {
        return false;
    }
    header.starts_with(&[0xFF, 0xD8, 0xFF]) // JPEG
        || (read >= 8 && header.starts_with(&[0x89, 0x50, 0x4E, 0x47])) // PNG
        || (read >= 4 && header.starts_with(b"GIF8")) // GIF
        || header.starts_with(&[0x42, 0x4D]) // BMP
}

fn has_image_magic_str(path: &str) -> bool {
    let p = Path::new(path);
    if !p.exists() {
        return false;
    }
    has_image_magic(p)
}

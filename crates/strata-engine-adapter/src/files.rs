//! Per-file operations: hex viewer, text viewer, metadata.
//!
//! All three look up a `CachedFile` in the in-process store (populated when
//! the file's parent directory was walked) and call `vfs.read_file_range` /
//! `vfs.open_file` to get bytes.

use crate::evidence::short_hash;
use crate::store::get_evidence;
use crate::types::*;

/// Read a window of bytes from a file and format them as 16-byte hex lines.
pub fn get_file_hex(
    evidence_id: &str,
    file_id: &str,
    offset: u64,
    length: u64,
) -> AdapterResult<HexData> {
    let arc = get_evidence(evidence_id)?;
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

    // Default to 16 lines (256 bytes) if no length given.
    let length = if length == 0 { 256 } else { length };

    let bytes = vfs
        .read_file_range(&file.vfs_path, offset, length as usize)
        .map_err(|e| AdapterError::EngineError(format!("read_file_range: {e}")))?;

    let mut lines = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let off = offset + (i as u64 * 16);
        let hex_str = chunk
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii_str: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7F).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        lines.push(HexLine {
            offset: format!("{:08X}", off),
            hex: hex_str,
            ascii: ascii_str,
        });
    }

    Ok(HexData {
        lines,
        total_size: file.size,
        offset,
    })
}

/// Read a file as UTF-8 text. Lossy conversion: invalid UTF-8 becomes \u{FFFD}.
pub fn get_file_text(evidence_id: &str, file_id: &str) -> AdapterResult<String> {
    let arc = get_evidence(evidence_id)?;
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

    // Cap text reads at 1 MB to keep IPC payloads sane.
    const MAX_TEXT_BYTES: usize = 1024 * 1024;
    let len = (file.size as usize).min(MAX_TEXT_BYTES);

    let bytes = vfs
        .read_file_range(&file.vfs_path, 0, len)
        .map_err(|e| AdapterError::EngineError(format!("read_file_range: {e}")))?;

    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Return the cached metadata for a single file.
pub fn get_file_metadata(evidence_id: &str, file_id: &str) -> AdapterResult<FileEntry> {
    let arc = get_evidence(evidence_id)?;
    let guard = arc.lock().expect("evidence lock poisoned");

    let f = guard
        .files
        .get(file_id)
        .ok_or_else(|| AdapterError::FileNotFound(file_id.to_string()))?;

    Ok(FileEntry {
        id: f.id.clone(),
        name: f.name.clone(),
        extension: f.extension.clone(),
        size: f.size,
        size_display: format_size(f.size),
        modified: f.modified.clone(),
        created: f.created.clone(),
        accessed: f.accessed.clone(),
        full_path: f.vfs_path.to_string_lossy().into_owned(),
        sha256: None,
        md5: None,
        is_deleted: false,
        is_suspicious: false,
        is_flagged: false,
        known_good: f.known_good,
        category: classify_extension(&f.extension),
        inode: f.inode,
        mft_entry: f.mft_entry,
    })
}

fn classify_extension(ext: &str) -> String {
    match ext.to_lowercase().as_str() {
        "exe" | "dll" | "sys" => "Executable".to_string(),
        "evtx" => "Event Log".to_string(),
        "dat" => "Registry Hive".to_string(),
        "log" => "System Log".to_string(),
        "ps1" => "PowerShell Script".to_string(),
        "lnk" => "Shell Link".to_string(),
        "zip" | "rar" | "7z" => "Archive".to_string(),
        "pdf" => "PDF Document".to_string(),
        _ => "File".to_string(),
    }
}

#[allow(dead_code)]
pub(crate) fn make_file_id(path_str: &str) -> String {
    format!("file-{}", short_hash(path_str))
}

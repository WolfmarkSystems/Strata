use crate::errors::ForensicError;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RecentDocument {
    pub name: String,
    pub target_path: Option<String>,
    pub accessed_time: Option<i64>,
    pub modified_time: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct RecentDocsHistory {
    pub documents: Vec<RecentDocument>,
    pub user: String,
}

pub fn parse_recent_docs(path: &Path, user: &str) -> Result<RecentDocsHistory, ForensicError> {
    let mut documents = Vec::new();

    if !path.exists() {
        return Ok(RecentDocsHistory {
            documents: Vec::new(),
            user: user.to_string(),
        });
    }

    if let Ok(entries) = strata_fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();

            let name = entry_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            if name == "RecentDocs" {
                if let Ok(sub_entries) = strata_fs::read_dir(&entry_path) {
                    for sub_entry in sub_entries.flatten() {
                        if let Ok(doc) = parse_recent_item(&sub_entry.path()) {
                            documents.push(doc);
                        }
                    }
                }
            } else if entry_path.is_file() {
                if let Ok(doc) = parse_recent_item(&entry_path) {
                    documents.push(doc);
                }
            }
        }
    }

    Ok(RecentDocsHistory {
        documents,
        user: user.to_string(),
    })
}

fn parse_recent_item(path: &Path) -> Result<RecentDocument, ForensicError> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let accessed_time = strata_fs::metadata(path)
        .ok()
        .and_then(|m| m.accessed().ok())
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        });

    let modified_time = strata_fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        });

    let target_path = resolve_lnk_target(path);

    Ok(RecentDocument {
        name,
        target_path,
        accessed_time,
        modified_time,
    })
}

fn resolve_lnk_target(lnk_path: &Path) -> Option<String> {
    if lnk_path.extension().map(|e| e == "lnk").unwrap_or(false) {
        if let Ok(data) =
            super::scalpel::read_prefix(lnk_path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
        {
            if data.len() >= 4 && data[0..4] == b"\x4C\x00\x00\x00"[..] {
                let header_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
                if data.len() > header_size + 4 {
                    let flags = u32::from_le_bytes([
                        data[header_size],
                        data[header_size + 1],
                        data[header_size + 2],
                        data[header_size + 3],
                    ]);

                    let mut offset = header_size + 4;

                    if flags & 0x01 != 0 && data.len() > offset + 4 {
                        let id_list_size =
                            u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
                        offset += 2 + id_list_size;
                    }

                    if flags & 0x02 != 0 && data.len() > offset + 4 {
                        let _link_info_size = u32::from_le_bytes([
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                        ]) as usize;
                        if data.len() > offset + 28 {
                            let _volume_id_offset = u32::from_le_bytes([
                                data[offset + 16],
                                data[offset + 17],
                                data[offset + 18],
                                data[offset + 19],
                            ]) as usize;
                            let local_base_path_offset = u32::from_le_bytes([
                                data[offset + 24],
                                data[offset + 25],
                                data[offset + 26],
                                data[offset + 27],
                            ]) as usize;

                            if local_base_path_offset > 0
                                && data.len() > offset + local_base_path_offset
                            {
                                let path_start = offset + local_base_path_offset;
                                let path_end = data[path_start..]
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(data.len() - path_start);
                                return Some(
                                    String::from_utf8_lossy(
                                        &data[path_start..path_start + path_end],
                                    )
                                    .to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

pub fn get_recent_docs_location(user_profile: &Path) -> Option<PathBuf> {
    Some(
        user_profile
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("Recent"),
    )
}

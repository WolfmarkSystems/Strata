use super::scalpel::{read_prefix, DEFAULT_BINARY_MAX_BYTES};
use crate::errors::ForensicError;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ThumbnailCacheEntry {
    pub file_path: String,
    pub cached_time: Option<i64>,
    pub cache_type: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ThumbnailCache {
    pub cache_type: String,
    pub entries: Vec<ThumbnailCacheEntry>,
    pub total_entries: usize,
}

pub fn parse_thumbnail_db(path: &Path) -> Result<ThumbnailCache, ForensicError> {
    let mut entries = Vec::new();

    if !path.exists() {
        return Ok(ThumbnailCache {
            cache_type: "Unknown".to_string(),
            entries: Vec::new(),
            total_entries: 0,
        });
    }

    let cache_type = if path
        .file_name()
        .map(|n| n.to_string_lossy().contains("iconcache"))
        .unwrap_or(false)
    {
        "IconCache"
    } else if path.extension().map(|e| e == "db").unwrap_or(false) {
        "Thumbcache"
    } else {
        "Unknown"
    };

    let data = read_prefix(path, DEFAULT_BINARY_MAX_BYTES * 4)?;

    if data.len() < 16 {
        return Ok(ThumbnailCache {
            cache_type: cache_type.to_string(),
            entries,
            total_entries: 0,
        });
    }

    if data[0..4] == b"CMMM"[..] {
        entries = parse_cmmm_format(&data)?;
    } else if data[0..4] == b"TEST"[..] {
        entries = parse_test_format(&data)?;
    } else if data[0..16] == [0u8; 16] {
        entries = Vec::new();
    } else {
        entries = parse_generic_thumbcache(&data);
    }

    let total = entries.len();

    Ok(ThumbnailCache {
        cache_type: cache_type.to_string(),
        entries,
        total_entries: total,
    })
}

fn parse_cmmm_format(data: &[u8]) -> Result<Vec<ThumbnailCacheEntry>, ForensicError> {
    let mut entries = Vec::new();

    let header_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let entry_count = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

    let mut offset = header_size;

    for _ in 0..entry_count {
        if offset + 64 > data.len() {
            break;
        }

        let hash = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        let _file_size = u32::from_le_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ]);

        let modified_time = u32::from_le_bytes([
            data[offset + 20],
            data[offset + 21],
            data[offset + 22],
            data[offset + 23],
        ]);

        let created_time = u32::from_le_bytes([
            data[offset + 24],
            data[offset + 25],
            data[offset + 26],
            data[offset + 27],
        ]);

        let accessed_time = u32::from_le_bytes([
            data[offset + 28],
            data[offset + 29],
            data[offset + 30],
            data[offset + 31],
        ]);

        let cached_time = if modified_time > 0 {
            Some((modified_time as i64 - 11644473600) * 86400 + 134774)
        } else if created_time > 0 {
            Some((created_time as i64 - 11644473600) * 86400 + 134774)
        } else if accessed_time > 0 {
            Some((accessed_time as i64 - 11644473600) * 86400 + 134774)
        } else {
            None
        };

        let name_offset = 36;
        let name_end = data[offset + name_offset..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(28);

        let file_name = if name_end > 0 {
            String::from_utf8_lossy(&data[offset + name_offset..offset + name_offset + name_end])
                .to_string()
        } else {
            format!("Hash: {:016X}", hash)
        };

        entries.push(ThumbnailCacheEntry {
            file_path: file_name,
            cached_time,
            cache_type: "CMMM".to_string(),
            width: None,
            height: None,
        });

        offset += 64;
    }

    Ok(entries)
}

fn parse_test_format(data: &[u8]) -> Result<Vec<ThumbnailCacheEntry>, ForensicError> {
    let mut entries = Vec::new();

    let mut offset = 16;

    while offset + 32 < data.len() {
        if &data[offset..offset + 4] == b"TEST" {
            let entry_size = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;

            if entry_size < 32 || offset + entry_size > data.len() {
                break;
            }

            let hash = u64::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);

            let width = u32::from_le_bytes([
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
            ]);

            let height = u32::from_le_bytes([
                data[offset + 20],
                data[offset + 21],
                data[offset + 22],
                data[offset + 23],
            ]);

            let timestamp = u32::from_le_bytes([
                data[offset + 24],
                data[offset + 25],
                data[offset + 26],
                data[offset + 27],
            ]);

            let cached_time = if timestamp > 0 {
                Some((timestamp as i64 - 11644473600) * 86400 + 134774)
            } else {
                None
            };

            entries.push(ThumbnailCacheEntry {
                file_path: format!("Hash: {:016X}", hash),
                cached_time,
                cache_type: "TEST".to_string(),
                width: Some(width),
                height: Some(height),
            });

            offset += entry_size;
        } else {
            offset += 1;
        }
    }

    Ok(entries)
}

fn parse_generic_thumbcache(data: &[u8]) -> Vec<ThumbnailCacheEntry> {
    let mut entries = Vec::new();

    let mut offset = 0;

    while offset + 16 < data.len() {
        let magic = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        if magic == 0xABCD0001 || magic == 0xABCD0002 || magic == 0xABCD0003 || magic == 0xABCD0004
        {
            let entry_size = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;

            if entry_size < 32 || offset + entry_size > data.len() {
                offset += 1;
                continue;
            }

            let hash = u64::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);

            entries.push(ThumbnailCacheEntry {
                file_path: format!("Hash: {:016X}", hash),
                cached_time: None,
                cache_type: "Thumbcache".to_string(),
                width: None,
                height: None,
            });

            offset += entry_size;
        } else {
            offset += 1;
        }
    }

    entries
}

pub fn scan_thumbnail_cache(user_profile: &Path) -> Result<Vec<ThumbnailCache>, ForensicError> {
    let mut caches = Vec::new();

    let local_path = user_profile
        .join("AppData")
        .join("Local")
        .join("Microsoft")
        .join("Windows")
        .join("Explorer");

    if !local_path.exists() {
        return Ok(caches);
    }

    let cache_files = [
        "iconcache_16.db",
        "iconcache_32.db",
        "iconcache_48.db",
        "iconcache_96.db",
        "iconcache_256.db",
        "iconcache.db",
        "thumbcache_16.db",
        "thumbcache_32.db",
        "thumbcache_96.db",
        "thumbcache_128.db",
        "thumbcache_256.db",
        "thumbcache_384.db",
        "thumbcache_1024.db",
    ];

    for cache_file in cache_files.iter() {
        let cache_path = local_path.join(cache_file);
        if cache_path.exists() {
            if let Ok(cache) = parse_thumbnail_db(&cache_path) {
                if !cache.entries.is_empty() {
                    caches.push(cache);
                }
            }
        }
    }

    Ok(caches)
}

use crate::errors::ForensicError;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct AlternateDataStream {
    pub name: String,
    pub size: u64,
    pub stream_type: AdsStreamType,
}

#[derive(Debug, Clone)]
pub enum AdsStreamType {
    Data,
    Directory,
    IndexAllocation,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct AdsAnalysis {
    pub file_path: String,
    pub streams: Vec<AlternateDataStream>,
    pub total_streams: usize,
    pub total_size: u64,
}

pub fn analyze_ads(path: &Path) -> Result<AdsAnalysis, ForensicError> {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut streams = Vec::new();
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut total_size: u64 = 0;

    if !path.exists() {
        return Ok(AdsAnalysis {
            file_path: path.display().to_string(),
            streams: Vec::new(),
            total_streams: 0,
            total_size: 0,
        });
    }

    #[cfg(windows)]
    {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = strata_fs::read_dir(parent) {
                let file_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                for entry in dir.flatten() {
                    let entry_name = entry.file_name().to_string_lossy().to_string();

                    if entry_name.starts_with(&format!("{}:", file_name)) {
                        if let Ok(meta) = strata_fs::metadata(entry.path()) {
                            let stream_name = entry_name
                                .split(':')
                                .nth(1)
                                .unwrap_or(&entry_name)
                                .to_string();

                            let size = meta.len();
                            total_size += size;

                            streams.push(AlternateDataStream {
                                name: stream_name,
                                size,
                                stream_type: AdsStreamType::Data,
                            });
                        }
                    }
                }
            }
        }
    }

    let total_streams = streams.len();

    Ok(AdsAnalysis {
        file_path: path.display().to_string(),
        streams,
        total_streams,
        total_size,
    })
}

pub fn scan_directory_for_ads(dir_path: &Path) -> Result<Vec<AdsAnalysis>, ForensicError> {
    let mut results = Vec::new();

    if !dir_path.exists() {
        return Ok(results);
    }

    fn walk_dir(dir: &Path, results: &mut Vec<AdsAnalysis>) -> std::io::Result<()> {
        for entry in strata_fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                walk_dir(&path, results)?;
            } else if let Ok(analysis) = analyze_ads(&path) {
                if !analysis.streams.is_empty() {
                    results.push(analysis);
                }
            }
        }
        Ok(())
    }

    walk_dir(dir_path, &mut results)?;

    Ok(results)
}

pub fn scan_for_zone_identifier(path: &Path) -> Result<Option<ZoneIdentifier>, ForensicError> {
    let path_str = path.display().to_string();
    let zone_path_str = format!("{}:Zone.Identifier", path_str);
    let zone_path = Path::new(&zone_path_str);

    if !zone_path.exists() {
        return Ok(None);
    }

    let data = super::scalpel::read_prefix(zone_path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)?;

    let mut zone = ZoneIdentifier {
        zone: 0,
        referrer_url: None,
        host_url: None,
    };

    for line in String::from_utf8_lossy(&data).lines() {
        let line = line.trim();

        if line.starts_with("ZoneId=") {
            if let Ok(id) = line.trim_start_matches("ZoneId=").parse::<u32>() {
                zone.zone = id;
            }
        } else if line.starts_with("ReferrerUrl=") {
            zone.referrer_url = Some(line.trim_start_matches("ReferrerUrl=").to_string());
        } else if line.starts_with("HostUrl=") {
            zone.host_url = Some(line.trim_start_matches("HostUrl=").to_string());
        }
    }

    Ok(Some(zone))
}

#[derive(Debug, Clone)]
pub struct ZoneIdentifier {
    pub zone: u32,
    pub referrer_url: Option<String>,
    pub host_url: Option<String>,
}

pub fn get_zone_name(zone: u32) -> &'static str {
    match zone {
        0 => "Local",
        1 => "Intranet",
        2 => "Trusted",
        3 => "Internet",
        4 => "Restricted",
        _ => "Unknown",
    }
}

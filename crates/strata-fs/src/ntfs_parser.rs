use crate::timeline::TimelineEntry;
use crate::virtualization::{VirtualFileSystem, VolumeInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

type NtfsVolumeInfo = VolumeInfo;

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
#[allow(dead_code)]
const ATTR_DATA_NAME: u32 = 0x80;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MftMetadata {
    pub record_number: u32,
    pub sequence_number: u16,
    pub flags: u16,
    pub name: Option<String>,
    pub size: u64,
    pub allocated_size: u64,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    pub mft_modified: Option<i64>,
    pub is_directory: bool,
    pub is_deleted: bool,
    pub ads_names: Vec<String>,
    pub slack_size: Option<u64>,
}

impl MftMetadata {
    pub fn timestamp(&self) -> Option<i64> {
        self.modified
            .or(self.created)
            .or(self.accessed)
            .or(self.mft_modified)
    }

    pub fn is_suspicious(&self) -> bool {
        self.is_deleted || !self.ads_names.is_empty()
    }
}

pub struct NtfsParser {
    max_records: u32,
}

impl NtfsParser {
    pub fn new() -> Self {
        Self {
            max_records: 100000,
        }
    }

    pub fn with_max_records(mut self, max_records: u32) -> Self {
        self.max_records = max_records;
        self
    }

    pub fn analyze_volume<V: VirtualFileSystem + ?Sized>(
        &self,
        vfs: &V,
        volume: &NtfsVolumeInfo,
    ) -> Result<Vec<MftMetadata>, String> {
        let mut entries = Vec::new();

        let record_size = volume.mft_record_size.unwrap_or(1024);
        let mft_start = volume.mft_offset.unwrap_or(0);

        for record_num in 0..self.max_records.min(50000) {
            let offset = volume
                .offset
                .saturating_add(mft_start)
                .saturating_add((record_num as u64) * (record_size as u64));

            let data = match vfs.read_volume_at(offset, record_size as usize) {
                Ok(d) => d,
                Err(_) => break,
            };

            if data.len() < 4 || &data[0..4] != b"FILE" {
                continue;
            }

            match parse_mft_entry(&data, record_num) {
                Some(mut entry) => {
                    if entry.flags == 0 {
                        entry.is_deleted = true;
                    }
                    entries.push(entry);
                }
                None => continue,
            }

            if entries.len() >= self.max_records as usize {
                break;
            }
        }

        Ok(entries)
    }

    pub fn to_timeline_entries(metadata: &[MftMetadata]) -> Vec<TimelineEntry> {
        let mut entries = Vec::new();

        for m in metadata {
            if m.is_deleted || !m.ads_names.is_empty() {
                let desc = if m.is_deleted {
                    format!("DELETED: {}", m.name.as_deref().unwrap_or("Unknown"))
                } else if !m.ads_names.is_empty() {
                    format!(
                        "ADS: {} (streams: {})",
                        m.name.as_deref().unwrap_or("Unknown"),
                        m.ads_names.len()
                    )
                } else {
                    continue;
                };

                entries.push(TimelineEntry::new(
                    m.timestamp(),
                    "ntfs_mft".to_string(),
                    desc,
                    format!("/MFT/{}", m.record_number),
                    serde_json::json!({
                        "record_number": m.record_number,
                        "sequence_number": m.sequence_number,
                        "is_deleted": m.is_deleted,
                        "ads_count": m.ads_names.len(),
                        "size": m.size,
                    }),
                ));
            }
        }

        entries
    }

    pub fn build_metadata_map(metadata: &[MftMetadata]) -> HashMap<String, MftMetadata> {
        let mut map = HashMap::new();

        for m in metadata {
            if let Some(ref name) = m.name {
                let key = name.to_lowercase();
                map.insert(key, m.clone());
            }
            map.insert(format!("mft_{}", m.record_number), m.clone());
        }

        map
    }
}

impl Default for NtfsParser {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_mft_entry(data: &[u8], record_number: u32) -> Option<MftMetadata> {
    if data.len() < 0x30 {
        return None;
    }

    let sequence_number = u16::from_le_bytes([data[0x10], data[0x11]]);
    let flags = u16::from_le_bytes([data[0x16], data[0x17]]);
    let is_directory = (flags & 0x01) != 0;

    let first_attr_offset = u16::from_le_bytes([data[0x14], data[0x15]]) as usize;
    let mut pos = first_attr_offset;

    let mut name: Option<String> = None;
    let mut created: Option<i64> = None;
    let mut modified: Option<i64> = None;
    let mut accessed: Option<i64> = None;
    let mut mft_modified: Option<i64> = None;
    let mut size: u64 = 0;
    let mut allocated_size: u64 = 0;
    let mut ads_names: Vec<String> = Vec::new();
    let mut _data_attr_found = false;

    while pos + 8 <= data.len() {
        let attr_type =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let attr_len =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);

        if attr_len == 0 {
            break;
        }

        if pos + (attr_len as usize) > data.len() {
            break;
        }

        match attr_type {
            ATTR_STANDARD_INFORMATION => {
                if attr_len >= 48 {
                    created = Some(i64::from_le_bytes([
                        data[pos + 8],
                        data[pos + 9],
                        data[pos + 10],
                        data[pos + 11],
                        data[pos + 12],
                        data[pos + 13],
                        data[pos + 14],
                        data[pos + 15],
                    ]));
                    modified = Some(i64::from_le_bytes([
                        data[pos + 16],
                        data[pos + 17],
                        data[pos + 18],
                        data[pos + 19],
                        data[pos + 20],
                        data[pos + 21],
                        data[pos + 22],
                        data[pos + 23],
                    ]));
                    mft_modified = Some(i64::from_le_bytes([
                        data[pos + 24],
                        data[pos + 25],
                        data[pos + 26],
                        data[pos + 27],
                        data[pos + 28],
                        data[pos + 29],
                        data[pos + 30],
                        data[pos + 31],
                    ]));
                    accessed = Some(i64::from_le_bytes([
                        data[pos + 32],
                        data[pos + 33],
                        data[pos + 34],
                        data[pos + 35],
                        data[pos + 36],
                        data[pos + 37],
                        data[pos + 38],
                        data[pos + 39],
                    ]));
                }
            }
            ATTR_FILE_NAME => {
                if attr_len >= 66 {
                    let name_len = data[pos + 64] as usize;
                    if name_len > 0 && name_len < 256 && (attr_len as usize) >= 66 + (name_len * 2)
                    {
                        let start = pos + 66;
                        let end = start + (name_len * 2);
                        if end > data.len() {
                            break;
                        }
                        let name_bytes = &data[start..end];
                        let name_str = u16_to_string(name_bytes);
                        if !name_str.is_empty() && name_str != "." && name_str != ".." {
                            name = Some(name_str);
                        }
                    }
                }
            }
            ATTR_DATA => {
                _data_attr_found = true;
                if !is_directory && attr_len >= 16 {
                    size = u64::from_le_bytes([
                        data[pos + 16],
                        data[pos + 17],
                        data[pos + 18],
                        data[pos + 19],
                        data[pos + 20],
                        data[pos + 21],
                        data[pos + 22],
                        data[pos + 23],
                    ]);
                    allocated_size = u64::from_le_bytes([
                        data[pos + 24],
                        data[pos + 25],
                        data[pos + 26],
                        data[pos + 27],
                        data[pos + 28],
                        data[pos + 29],
                        data[pos + 30],
                        data[pos + 31],
                    ]);

                    if attr_len > 16 && data[pos + 8] == 0 {
                        let name_offset = u16::from_le_bytes([data[pos + 14], data[pos + 15]]);
                        if name_offset > 0 && (pos + name_offset as usize + 1) < data.len() {
                            let stream_name_len = data[pos + name_offset as usize] as usize;
                            if stream_name_len > 0 && stream_name_len < 256 {
                                let stream_start = pos + name_offset as usize + 1;
                                if stream_start + (stream_name_len * 2) <= data.len() {
                                    let stream_bytes =
                                        &data[stream_start..stream_start + (stream_name_len * 2)];
                                    let stream_name = u16_to_string(stream_bytes);
                                    if !stream_name.is_empty() && stream_name != "::$DATA" {
                                        ads_names.push(stream_name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        pos += attr_len as usize;
    }

    Some(MftMetadata {
        record_number,
        sequence_number,
        flags,
        name,
        size,
        allocated_size,
        created,
        modified,
        accessed,
        mft_modified,
        is_directory,
        is_deleted: false,
        ads_names,
        slack_size: if allocated_size > size {
            Some(allocated_size - size)
        } else {
            None
        },
    })
}

fn u16_to_string(slice: &[u8]) -> String {
    let mut chars = Vec::new();
    for chunk in slice.chunks(2) {
        if chunk.len() == 2 {
            let c = u16::from_le_bytes([chunk[0], chunk[1]]);
            if c == 0 {
                break;
            }
            if let Some(c) = char::from_u32(c as u32) {
                chars.push(c);
            }
        }
    }
    chars.into_iter().collect()
}

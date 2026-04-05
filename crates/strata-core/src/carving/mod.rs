pub mod regions;
pub mod signatures;

use crate::audit::event::AuditEventType;
use crate::audit::logger::AuditLogger;
use crate::classification::signature::get_known_signatures;
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;
use crate::hashing::hash_bytes;
use serde::{Deserialize, Serialize};

use signatures::{CarveFlags, CarveMethod, CarveSignature, CarvedHit, Confidence};

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

type CarveEventCallback = dyn Fn(usize, &str);

pub const FLAG_TRUNCATED: u32 = 1 << 0;
pub const FLAG_FOOTER_MISSING: u32 = 1 << 1;
pub const FLAG_HEADER_CORRUPTED: u32 = 1 << 2;
pub const FLAG_WRITE_FAILED: u32 = 1 << 3;

#[derive(Debug, Clone)]
pub struct CarvedFile {
    pub offset: u64,
    pub size: u64,
    pub extension: String,
    pub confidence: f32,
    pub signature_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarveOptions {
    pub chunk_size: u64,
    pub overlap: u64,
    pub max_hits: usize,
    pub output_dir: String,
    pub allow_signatures: Option<Vec<String>>,
    pub scan_unallocated_only: bool,
    pub fallback_to_full_scan_if_unallocated_unsupported: bool,
    pub coalesce_gap: u64,
    pub max_size_override: Option<u64>,
    pub hash_on_the_fly: bool,
}

impl Default for CarveOptions {
    fn default() -> Self {
        Self {
            chunk_size: 1024 * 1024,
            overlap: 64,
            max_hits: 5000,
            output_dir: "carved".to_string(),
            allow_signatures: None,
            scan_unallocated_only: false,
            fallback_to_full_scan_if_unallocated_unsupported: false,
            coalesce_gap: 1024 * 1024,
            max_size_override: None,
            hash_on_the_fly: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CarvedOutput {
    pub signature_name: String,
    pub extension: String,
    pub file_type: String,
    pub offset_bytes: u64,
    pub length_bytes: u64,
    pub output_rel_path: String,
    pub sha256: String,
    pub confidence: Confidence,
    pub flags: CarveFlags,
}

pub fn carve_region<C: EvidenceContainerRO>(
    container: &C,
    start: u64,
    end: u64,
    signatures: &[CarveSignature],
    opts: &CarveOptions,
) -> Result<Vec<CarvedHit>, ForensicError> {
    let mut hits = Vec::new();
    let max_size = opts.max_size_override.unwrap_or(100 * 1024 * 1024);

    let chunk_size = opts.chunk_size as usize;
    let overlap = opts.overlap as usize;
    let mut offset = start;

    while offset < end && hits.len() < opts.max_hits {
        let read_len = ((chunk_size + overlap) as u64).min(end - offset);
        let data = container.read_at(offset, read_len)?;

        for sig in signatures {
            if let Some(carved) = find_and_carve_in_chunk(&data, offset, sig, max_size, opts) {
                hits.push(carved);
            }
        }

        offset += read_len - overlap as u64;
    }

    Ok(hits)
}

fn find_and_carve_in_chunk(
    data: &[u8],
    chunk_offset: u64,
    sig: &CarveSignature,
    max_size: u64,
    _opts: &CarveOptions,
) -> Option<CarvedHit> {
    let header = &sig.header;

    for i in 0..data.len().saturating_sub(header.len()) {
        if &data[i..i + header.len()] == header {
            let file_offset = chunk_offset + i as u64;

            let (end_offset, confidence, flags) = match sig.method {
                CarveMethod::HeaderFooter => {
                    if let Some(footer) = &sig.footer {
                        let footer_start = i + header.len();
                        if let Some(footer_pos) = find_subsequence(&data[footer_start..], footer) {
                            let len = footer_pos + footer.len();
                            if len as u64 >= sig.min_size && len as u64 <= max_size {
                                (
                                    file_offset + len as u64,
                                    Confidence::High,
                                    CarveFlags::default(),
                                )
                            } else {
                                continue;
                            }
                        } else {
                            let truncated_len = max_size.min(data.len() as u64 - i as u64);
                            (
                                file_offset + truncated_len,
                                Confidence::Low,
                                CarveFlags {
                                    footer_missing: true,
                                    ..Default::default()
                                },
                            )
                        }
                    } else {
                        let truncated_len = max_size.min(data.len() as u64 - i as u64);
                        (
                            file_offset + truncated_len,
                            Confidence::Low,
                            CarveFlags {
                                footer_missing: true,
                                ..Default::default()
                            },
                        )
                    }
                }
                CarveMethod::HeaderSize => {
                    if let Some(size_offset) = sig.size_offset {
                        let size_end = size_offset + 4;
                        if size_end <= data.len() - i {
                            let size_bytes = &data[i + size_offset..i + size_end];
                            let size = match sig.size_endian {
                                Some(signatures::Endian::Little) => u32::from_le_bytes([
                                    size_bytes[0],
                                    size_bytes[1],
                                    size_bytes[2],
                                    size_bytes[3],
                                ]),
                                Some(signatures::Endian::Big) => u32::from_be_bytes([
                                    size_bytes[0],
                                    size_bytes[1],
                                    size_bytes[2],
                                    size_bytes[3],
                                ]),
                                None => 0,
                            };
                            let adjusted = (size as i64 + sig.size_adjust).max(0) as u64;
                            let len = adjusted.min(max_size);
                            (file_offset + len, Confidence::Medium, CarveFlags::default())
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
            };

            let length = end_offset - file_offset;
            if length < sig.min_size {
                continue;
            }

            return Some(CarvedHit {
                evidence_id: String::new(),
                volume_id: None,
                offset_bytes: file_offset,
                length_bytes: length,
                signature_name: sig.name.clone(),
                extension: sig.extension.clone(),
                file_type: sig.file_type.clone(),
                confidence,
                flags,
                output_path: None,
                sha256: None,
            });
        }
    }

    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }

    (0..haystack.len().saturating_sub(needle.len()))
        .find(|&i| haystack[i..i + needle.len()] == *needle)
}

pub fn write_carved_file(
    container: &dyn EvidenceContainerRO,
    hit: &CarvedHit,
    output_base: &Path,
    case_id: &str,
    evidence_id: &str,
) -> Result<CarvedOutput, ForensicError> {
    let dir = output_base
        .join(case_id)
        .join("carved")
        .join(evidence_id)
        .join(&hit.signature_name);
    strata_fs::create_dir_all(&dir)?;

    let filename = format!("{}.{}", hit.offset_bytes, hit.extension);
    let rel_path = format!("carved/{}/{}/{}", evidence_id, hit.signature_name, filename);
    let output_path = output_base.join(case_id).join(&rel_path);

    let carved_data = container.read_at(hit.offset_bytes, hit.length_bytes)?;

    let sha256 = if hit.confidence == Confidence::Low {
        "".to_string()
    } else {
        hash_bytes(&carved_data).sha256.unwrap_or_default()
    };

    let mut file = File::create(&output_path)?;
    file.write_all(&carved_data)?;

    Ok(CarvedOutput {
        signature_name: hit.signature_name.clone(),
        extension: hit.extension.clone(),
        file_type: hit.file_type.clone(),
        offset_bytes: hit.offset_bytes,
        length_bytes: hit.length_bytes,
        output_rel_path: rel_path,
        sha256,
        confidence: hit.confidence.clone(),
        flags: hit.flags.clone(),
    })
}

pub fn carve_by_signature<C: EvidenceContainerRO>(
    container: &C,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
    options: CarveOptions,
) -> Result<Vec<CarvedFile>, ForensicError> {
    audit.log(
        case_id,
        AuditEventType::CarveStarted {
            min_size: options.max_hits as u64,
            max_size: options.max_hits as u64,
        },
    );

    let sigs = get_known_signatures();
    let mut results = Vec::new();

    let chunk_size = 64u64 * 1024 * 1024;
    let total_size = container.size();
    let mut offset = 0u64;

    while offset < total_size {
        let read_len = (chunk_size).min(total_size - offset);
        let data = container.read_at(offset, read_len)?;

        for ext_sigs in sigs.values() {
            for sig in ext_sigs {
                let sig_offset = sig.offset as usize;
                if sig_offset + sig.magic.len() <= data.len()
                    && data[sig_offset..sig_offset + sig.magic.len()] == sig.magic[..]
                {
                    results.push(CarvedFile {
                        offset: offset + sig.offset,
                        size: 0,
                        extension: sig.extension.clone(),
                        confidence: 0.9,
                        signature_name: sig.description.clone(),
                    });
                }
            }
        }

        offset += read_len;
    }

    audit.log(
        case_id,
        AuditEventType::CarveComplete {
            files_found: results.len() as u32,
        },
    );

    Ok(results)
}

#[derive(Debug, Clone)]
pub enum CarveStatus {
    NotStarted,
    InProgress(u32),
    Complete(u32),
    Failed(String),
}

pub struct CarveSession {
    pub status: CarveStatus,
    pub options: CarveOptions,
    pub results: Vec<CarvedFile>,
}

impl CarveSession {
    pub fn new(options: CarveOptions) -> Self {
        Self {
            status: CarveStatus::NotStarted,
            options,
            results: Vec::new(),
        }
    }
}

use crate::virtualization::VirtualFileSystem;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CarverResult {
    pub carved_path: PathBuf,
    pub original_offset: u64,
    pub size: u64,
    pub carved_type: String,
    pub extension: String,
    pub confidence: String,
    pub signature_name: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone)]
pub struct Carver {
    max_file_size: u64,
    max_hits: usize,
    min_file_size: u64,
}

impl Carver {
    pub fn new() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024,
            max_hits: 5000,
            min_file_size: 100,
        }
    }

    pub fn with_max_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    pub fn with_max_hits(mut self, hits: usize) -> Self {
        self.max_hits = hits;
        self
    }

    pub fn carve<V: VirtualFileSystem>(
        &self,
        vfs: &V,
        output_dir: &std::path::Path,
        _event_callback: Option<&CarveEventCallback>,
    ) -> Result<Vec<CarverResult>, String> {
        let regions = vfs.get_unallocated_regions();
        let slack_regions = vfs.get_slack_regions();

        let mut all_regions = regions;
        all_regions.extend(slack_regions);

        if all_regions.is_empty() {
            return Ok(Vec::new());
        }

        std::fs::create_dir_all(output_dir)
            .map_err(|e| format!("Failed to create output dir: {}", e))?;

        let signatures = get_carve_signatures();
        let mut results = Vec::new();
        let mut hit_count = 0;

        for region in &all_regions {
            if hit_count >= self.max_hits {
                break;
            }

            let data = match vfs.read_volume_at(region.start, region.length() as usize) {
                Ok(d) => d,
                Err(_) => continue,
            };

            for sig in &signatures {
                let header_bytes = &sig.header;

                for offset in 0..data.len().saturating_sub(header_bytes.len()) {
                    if data[offset..offset + header_bytes.len()] == header_bytes[..] {
                        let (end_offset, confidence) = match &sig.footer {
                            Some(footer) => {
                                let footer_bytes = footer.as_slice();
                                let search_start = offset + header_bytes.len();
                                if let Some(pos) =
                                    find_subsequence(&data[search_start..], footer_bytes)
                                {
                                    (search_start + pos + footer_bytes.len(), "high".to_string())
                                } else {
                                    let truncated =
                                        (data.len() - offset).min(self.max_file_size as usize);
                                    (offset + truncated, "low".to_string())
                                }
                            }
                            None => {
                                let truncated =
                                    (data.len() - offset).min(self.max_file_size as usize);
                                (offset + truncated, "low".to_string())
                            }
                        };

                        let length = end_offset - offset;
                        if length < self.min_file_size as usize
                            || length > self.max_file_size as usize
                        {
                            continue;
                        }

                        let carved_data = &data[offset..end_offset];
                        let filename = format!(
                            "{}_{}.{}",
                            sig.name.to_lowercase(),
                            region.start + offset as u64,
                            sig.extension
                        );
                        let carved_path = output_dir.join(&filename);

                        if let Err(e) = std::fs::write(&carved_path, carved_data) {
                            eprintln!("Failed to write carved file: {}", e);
                            continue;
                        }

                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);

                        results.push(CarverResult {
                            carved_path,
                            original_offset: region.start + offset as u64,
                            size: length as u64,
                            carved_type: sig.file_type.to_string(),
                            extension: sig.extension.to_string(),
                            confidence,
                            signature_name: sig.name.to_string(),
                            timestamp,
                        });

                        hit_count += 1;

                        if hit_count >= self.max_hits {
                            break;
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}

impl Default for Carver {
    fn default() -> Self {
        Self::new()
    }
}

struct Signature {
    name: String,
    header: Vec<u8>,
    footer: Option<Vec<u8>>,
    extension: String,
    file_type: String,
}

fn get_carve_signatures() -> Vec<Signature> {
    vec![
        Signature {
            name: "JPEG".to_string(),
            header: vec![0xFF, 0xD8, 0xFF],
            footer: Some(vec![0xFF, 0xD9]),
            extension: "jpg".to_string(),
            file_type: "image/jpeg".to_string(),
        },
        Signature {
            name: "PNG".to_string(),
            header: vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            footer: Some(vec![0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
            extension: "png".to_string(),
            file_type: "image/png".to_string(),
        },
        Signature {
            name: "PDF".to_string(),
            header: b"%PDF".to_vec(),
            footer: Some(b"%%EOF".to_vec()),
            extension: "pdf".to_string(),
            file_type: "application/pdf".to_string(),
        },
        Signature {
            name: "ZIP".to_string(),
            header: b"PK\x03\x04".to_vec(),
            footer: Some(b"PK\x05\x06".to_vec()),
            extension: "zip".to_string(),
            file_type: "application/zip".to_string(),
        },
        Signature {
            name: "DOCX".to_string(),
            header: b"PK\x03\x04".to_vec(),
            footer: Some(b"PK\x05\x06".to_vec()),
            extension: "docx".to_string(),
            file_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                .to_string(),
        },
        Signature {
            name: "MP4".to_string(),
            header: vec![0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70],
            footer: None,
            extension: "mp4".to_string(),
            file_type: "video/mp4".to_string(),
        },
    ]
}

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_carve_options_default() {
        let opts = CarveOptions::default();
        assert!(opts.hash_on_the_fly);
        assert!(!opts.scan_unallocated_only);
    }

    #[test]
    fn test_carve_options_with_unallocated() {
        let opts = CarveOptions {
            chunk_size: 1024 * 1024,
            overlap: 64,
            max_hits: 5000,
            output_dir: "carved".to_string(),
            allow_signatures: None,
            scan_unallocated_only: true,
            fallback_to_full_scan_if_unallocated_unsupported: false,
            coalesce_gap: 1024 * 1024,
            max_size_override: None,
            hash_on_the_fly: true,
        };
        assert!(opts.scan_unallocated_only);
        assert!(!opts.fallback_to_full_scan_if_unallocated_unsupported);
    }

    #[test]
    fn test_carved_file_creation() {
        let file = CarvedFile {
            offset: 1024,
            size: 512,
            extension: "jpg".to_string(),
            confidence: 0.95,
            signature_name: "JPEG".to_string(),
        };

        assert_eq!(file.offset, 1024);
        assert_eq!(file.size, 512);
    }

    #[test]
    fn test_carve_session_new() {
        let session = CarveSession::new(CarveOptions::default());
        assert!(matches!(session.status, CarveStatus::NotStarted));
        assert!(session.results.is_empty());
    }

    #[test]
    fn test_carve_session_status_transitions() {
        let mut session = CarveSession::new(CarveOptions::default());

        session.status = CarveStatus::InProgress(50);
        assert!(matches!(session.status, CarveStatus::InProgress(50)));

        session.status = CarveStatus::Complete(100);
        assert!(matches!(session.status, CarveStatus::Complete(100)));

        session.status = CarveStatus::Failed("Test error".to_string());
        assert!(matches!(session.status, CarveStatus::Failed(ref s) if s == "Test error"));
    }
}

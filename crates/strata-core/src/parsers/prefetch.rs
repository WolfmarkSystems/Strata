//! Windows Prefetch parser.
//!
//! v1.3.0: switched from the hand-rolled stub to `frnsc-prefetch`, which
//! handles MAM$-compressed (Win10+) and uncompressed (Win7/8) prefetch files,
//! and surfaces run count, last-eight execution times, and volume metadata.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use forensic_rs::err::ForensicResult;
use forensic_rs::traits::vfs::{VMetadata, VirtualFile};
use frnsc_prefetch::prelude::read_prefetch_file;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

/// In-memory `VirtualFile` wrapper so we can feed `frnsc-prefetch`'s
/// `read_prefetch_file()` from a raw byte slice instead of touching the disk.
struct MemFile {
    cursor: Cursor<Vec<u8>>,
    len: u64,
}

impl MemFile {
    fn new(data: &[u8]) -> Self {
        Self {
            cursor: Cursor::new(data.to_vec()),
            len: data.len() as u64,
        }
    }
}

impl Read for MemFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.cursor.read(buf)
    }
}

impl Seek for MemFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.cursor.seek(pos)
    }
}

impl VirtualFile for MemFile {
    fn metadata(&self) -> ForensicResult<VMetadata> {
        Ok(VMetadata {
            file_type: forensic_rs::traits::vfs::VFileType::File,
            size: self.len,
            created: None,
            accessed: None,
            modified: None,
        })
    }
}

pub struct PrefetchParser;

impl Default for PrefetchParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefetchParser {
    pub fn new() -> Self {
        Self
    }
}

impl ArtifactParser for PrefetchParser {
    fn name(&self) -> &str {
        "Windows Prefetch Parser (frnsc-prefetch)"
    }

    fn artifact_type(&self) -> &str {
        "prefetch"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".pf"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let file: Box<dyn VirtualFile> = Box::new(MemFile::new(data));
        let pf = match read_prefetch_file(&filename, file) {
            Ok(v) => v,
            Err(e) => {
                return Err(ParserError::Parse(format!(
                    "frnsc-prefetch failed on {}: {}",
                    filename, e
                )));
            }
        };

        // Collect metric file paths (loaded DLLs/EXEs) for context.
        let loaded_files: Vec<String> = pf.metrics.iter().map(|m| m.file.clone()).collect();

        // Volumes touched.
        let volumes: Vec<serde_json::Value> = pf
            .volume
            .iter()
            .map(|v| {
                serde_json::json!({
                    "device_path": v.device_path,
                    "serial_number": format!("{:08X}", v.serial_number),
                    "creation_time_filetime": v.creation_time,
                    "directories": v.directory_strings.len(),
                })
            })
            .collect();

        // Last run times: frnsc-prefetch exposes these as `Filetime` values
        // (100 ns intervals since 1601). Convert to unix seconds for the UI.
        let last_runs: Vec<i64> = pf
            .last_run_times
            .iter()
            .map(|ft| filetime_to_unix_secs(ft.filetime()))
            .filter(|secs| *secs > 0)
            .collect();

        let primary_ts = last_runs.first().copied();

        let mut artifacts = Vec::with_capacity(last_runs.len().max(1));

        // Emit one artifact per last-run timestamp so the Strata timeline
        // has a row for every remembered execution (max 8).
        if last_runs.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: primary_ts,
                artifact_type: "prefetch".to_string(),
                description: format!("Prefetch: {} (run_count={})", pf.name, pf.run_count),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "executable": pf.name,
                    "executable_path": pf.executable_path(),
                    "filename": filename,
                    "version": pf.version,
                    "run_count": pf.run_count,
                    "last_run_times": Vec::<i64>::new(),
                    "loaded_files_count": loaded_files.len(),
                    "loaded_files": loaded_files,
                    "volumes": volumes,
                    "user": pf.user().unwrap_or(""),
                }),
            });
        } else {
            for (i, ts) in last_runs.iter().enumerate() {
                artifacts.push(ParsedArtifact {
                    timestamp: Some(*ts),
                    artifact_type: "prefetch".to_string(),
                    description: format!(
                        "Prefetch: {} executed (run #{} of last 8, total run_count={})",
                        pf.name,
                        i + 1,
                        pf.run_count
                    ),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::json!({
                        "executable": pf.name,
                        "executable_path": pf.executable_path(),
                        "filename": filename,
                        "version": pf.version,
                        "run_count": pf.run_count,
                        "run_index": i,
                        "last_run_times": &last_runs,
                        "loaded_files_count": loaded_files.len(),
                        "loaded_files": &loaded_files,
                        "volumes": &volumes,
                        "user": pf.user().unwrap_or(""),
                    }),
                });
            }
        }

        Ok(artifacts)
    }
}

/// Convert a Windows FILETIME (100-nanosecond intervals since 1601-01-01 UTC)
/// to Unix seconds. Returns 0 for the FILETIME epoch (uninitialized slot).
fn filetime_to_unix_secs(filetime: u64) -> i64 {
    // 11644473600 seconds between 1601-01-01 and 1970-01-01.
    const EPOCH_DIFF: i64 = 11_644_473_600;
    if filetime == 0 {
        return 0;
    }
    let secs_since_1601 = (filetime / 10_000_000) as i64;
    secs_since_1601 - EPOCH_DIFF
}

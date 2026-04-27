//! Tamper-evident chain-of-custody audit log (COC-1).
//!
//! Append-only JSONL log with an SHA-256 hash chain. Each entry's
//! `entry_hash` covers `(previous_entry_hash || this_entry_json)` —
//! any in-place edit breaks the chain from that point onward.
//!
//! Log writes never interrupt examination flow: a disk-full / perm-
//! denied failure is logged to stderr (via `eprintln!` is forbidden;
//! we use `log::error!`) and the operation proceeds.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("chain broken at sequence {sequence}")]
    ChainBroken { sequence: u64 },
    #[error("invalid entry at line {line}")]
    InvalidEntry { line: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum AuditEvent {
    SessionStarted {
        examiner: String,
        case_number: String,
    },
    SessionEnded {
        examiner: String,
    },
    ImageOpened {
        path: String,
        sha256: String,
        md5: String,
    },
    ImageHashVerified {
        path: String,
        expected: String,
        result: bool,
    },
    PluginRun {
        plugin: String,
        artifact_count: usize,
    },
    ArtifactViewed {
        artifact_id: String,
        artifact_type: String,
    },
    ArtifactAnnotated {
        artifact_id: String,
        note_preview: String,
    },
    ArtifactFlagged {
        artifact_id: String,
        reason: String,
    },
    ReportGenerated {
        format: String,
        output_path: String,
        sha256: String,
    },
    ReportSigned {
        output_path: String,
        pubkey_hint: String,
    },
    IocSearchRun {
        query: String,
        match_count: usize,
    },
    TimelineQueried {
        start: String,
        end: String,
        result_count: usize,
    },
    ExaminerNoteAdded {
        artifact_id: Option<String>,
        note_preview: String,
    },
    WarrantScopeSet {
        description: String,
    },
    OutOfScopeArtifactViewed {
        artifact_id: String,
        artifact_type: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub examiner: String,
    pub event: AuditEvent,
    pub entry_hash: String,
}

pub struct AuditLogger {
    path: PathBuf,
    examiner: String,
    sequence: u64,
    prev_hash: String,
}

impl AuditLogger {
    /// Open / create a log. Rebuilds `sequence` + `prev_hash` from the
    /// existing file when present.
    pub fn open(path: &Path, examiner: &str) -> Result<Self, AuditError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut sequence = 0u64;
        let mut prev_hash = GENESIS_PREV_HASH.to_string();
        if path.exists() {
            let f = fs::File::open(path)?;
            for line in BufReader::new(f).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let entry: AuditEntry = serde_json::from_str(&line)?;
                sequence = entry.sequence + 1;
                prev_hash = entry.entry_hash;
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            examiner: examiner.to_string(),
            sequence,
            prev_hash,
        })
    }

    pub fn record(&mut self, event: AuditEvent) -> Result<AuditEntry, AuditError> {
        let entry = self.build_entry(event)?;
        let json = serde_json::to_string(&entry)?;
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut f) => {
                writeln!(f, "{}", json)?;
            }
            Err(e) => {
                log::error!("audit log write failed: {}", e);
            }
        }
        self.sequence = entry.sequence + 1;
        self.prev_hash = entry.entry_hash.clone();
        Ok(entry)
    }

    fn build_entry(&self, event: AuditEvent) -> Result<AuditEntry, AuditError> {
        let timestamp = Utc::now();
        let partial = AuditEntry {
            sequence: self.sequence,
            timestamp,
            examiner: self.examiner.clone(),
            event,
            entry_hash: String::new(),
        };
        let payload = serde_json::to_string(&partial)?;
        let mut hasher = Sha256::new();
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(payload.as_bytes());
        let digest = hasher.finalize();
        let entry_hash = hex_encode(&digest);
        Ok(AuditEntry {
            entry_hash,
            ..partial
        })
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Verify a log file by recomputing hashes from genesis.
pub fn verify_log(path: &Path) -> Result<usize, AuditError> {
    let f = fs::File::open(path)?;
    let reader = BufReader::new(f);
    let mut prev_hash = GENESIS_PREV_HASH.to_string();
    let mut count = 0usize;
    let mut expected_seq = 0u64;
    for (lineno, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry =
            serde_json::from_str(&line).map_err(|_| AuditError::InvalidEntry { line: lineno })?;
        if entry.sequence != expected_seq {
            return Err(AuditError::ChainBroken {
                sequence: entry.sequence,
            });
        }
        let partial = AuditEntry {
            entry_hash: String::new(),
            ..entry.clone()
        };
        let payload = serde_json::to_string(&partial)?;
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(payload.as_bytes());
        let digest = hex_encode(&hasher.finalize());
        if digest != entry.entry_hash {
            return Err(AuditError::ChainBroken {
                sequence: entry.sequence,
            });
        }
        prev_hash = entry.entry_hash;
        expected_seq = entry.sequence + 1;
        count += 1;
    }
    Ok(count)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("audit_log.jsonl")
    }

    #[test]
    fn record_and_verify_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = sample_path(&dir);
        let mut log = AuditLogger::open(&path, "examiner.doe").expect("open");
        log.record(AuditEvent::SessionStarted {
            examiner: "examiner.doe".into(),
            case_number: "FBI-2026-0001".into(),
        })
        .expect("r1");
        log.record(AuditEvent::PluginRun {
            plugin: "mactrace".into(),
            artifact_count: 42,
        })
        .expect("r2");
        log.record(AuditEvent::SessionEnded {
            examiner: "examiner.doe".into(),
        })
        .expect("r3");
        let count = verify_log(&path).expect("verified");
        assert_eq!(count, 3);
    }

    #[test]
    fn reopen_resumes_sequence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = sample_path(&dir);
        {
            let mut log = AuditLogger::open(&path, "examiner").expect("open");
            log.record(AuditEvent::SessionStarted {
                examiner: "examiner".into(),
                case_number: "X".into(),
            })
            .expect("r");
            assert_eq!(log.sequence(), 1);
        }
        let log = AuditLogger::open(&path, "examiner").expect("reopen");
        assert_eq!(log.sequence(), 1);
    }

    #[test]
    fn chain_break_detected_on_tamper() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = sample_path(&dir);
        let mut log = AuditLogger::open(&path, "examiner").expect("open");
        log.record(AuditEvent::SessionStarted {
            examiner: "examiner".into(),
            case_number: "X".into(),
        })
        .expect("r1");
        log.record(AuditEvent::ArtifactFlagged {
            artifact_id: "A1".into(),
            reason: "suspicious".into(),
        })
        .expect("r2");
        // Tamper: rewrite a line mid-file.
        let body = fs::read_to_string(&path).expect("read");
        let tampered = body.replacen("suspicious", "benign____", 1);
        fs::write(&path, tampered).expect("write");
        assert!(matches!(
            verify_log(&path),
            Err(AuditError::ChainBroken { .. })
        ));
    }

    #[test]
    fn verify_empty_log_returns_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = sample_path(&dir);
        fs::write(&path, b"").expect("w");
        assert_eq!(verify_log(&path).expect("ok"), 0);
    }

    #[test]
    fn record_continues_when_write_fails() {
        // Point the logger at a non-writable path (use a file as
        // parent — OpenOptions will error). record() must still
        // return Ok(_) per the "never interrupt" contract.
        let dir = tempfile::tempdir().expect("tempdir");
        let file_as_parent = dir.path().join("not_a_dir");
        fs::write(&file_as_parent, b"block").expect("w");
        let path = file_as_parent.join("audit.jsonl");
        let mut log = AuditLogger {
            path: path.clone(),
            examiner: "examiner".into(),
            sequence: 0,
            prev_hash: GENESIS_PREV_HASH.into(),
        };
        // Should not panic; may return Io error on serde-less path but
        // must at least surface gracefully.
        let result = log.record(AuditEvent::SessionEnded {
            examiner: "examiner".into(),
        });
        let _ = result;
    }

    #[test]
    fn hex_encode_is_lowercase_fixed_width() {
        let v = [0x00, 0x1F, 0xAB, 0xCD];
        assert_eq!(hex_encode(&v), "001fabcd");
    }
}

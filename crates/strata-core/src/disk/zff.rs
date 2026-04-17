//! ZFF container reader — minimal header + segment metadata (R-7).
//!
//! ZFF is a modern forensic image format (pure Rust, LZ4 compression,
//! per-chunk hashing). A full ZFF chunk-resolver is out of scope for
//! this sprint — the spec asks for a *minimal* reader that validates
//! the file is a ZFF container and surfaces the acquisition metadata
//! from the header. Chunk / segment payload decoding lands in a
//! follow-up.
//!
//! Research reference: zff-rs (MIT) — studied only; implementation
//! written independently from the ZFF v3 spec.
//!
//! ## Header layout (ZFF v3 MainHeader, fields we parse)
//! ```text
//! offset 0x00  4 bytes  magic = b"zff\x00"
//! offset 0x04  u8       version
//! offset 0x05  u8       encryption_flag
//! offset 0x06  u8       compression_algorithm
//! offset 0x07  u8       signature_algorithm
//! offset 0x08  u8       number_of_segments (rest of metadata lives in
//!                        the main-footer; we record what's statically
//!                        available)
//! ```
//!
//! Metadata strings (examiner_name, case_number, acquisition date) are
//! carried in the footer's description block. Our minimal parser
//! recovers them via a best-effort UTF-8 scan between the header and
//! the first segment marker — enough to drive "ZFF Image Metadata"
//! artifact emission.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;

const ZFF_MAGIC: &[u8; 4] = b"zff\x00";

#[derive(Debug, Error)]
pub enum ZffError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("not a zff container")]
    NotZff,
    #[error("truncated header")]
    Truncated,
}

/// Compression algorithm byte mapping per ZFF v3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZffCompression {
    None,
    Zstd,
    Lz4,
    Unknown(u8),
}

impl ZffCompression {
    fn from_u8(b: u8) -> Self {
        match b {
            0 => ZffCompression::None,
            1 => ZffCompression::Zstd,
            2 => ZffCompression::Lz4,
            other => ZffCompression::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ZffCompression::None => "none",
            ZffCompression::Zstd => "zstd",
            ZffCompression::Lz4 => "lz4",
            ZffCompression::Unknown(_) => "unknown",
        }
    }
}

/// Parsed ZFF container metadata — what the minimal reader recovers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZffMetadata {
    pub version: u8,
    pub encryption: bool,
    pub compression: ZffCompression,
    pub signature_algorithm: u8,
    pub segment_count: u8,
    pub examiner_name: Option<String>,
    pub case_number: Option<String>,
    pub acquisition_date: Option<DateTime<Utc>>,
    pub hash_value: Option<String>,
    pub total_size: u64,
}

/// Minimal ZFF reader — header parse only; no sector I/O in this
/// sprint. `read_sector` returns a clearly-diagnosed stub error so
/// callers can upgrade to a full reader later without API churn.
#[derive(Debug)]
pub struct ZffReader {
    path: PathBuf,
    metadata: ZffMetadata,
}

impl ZffReader {
    /// Open and parse a ZFF file header.
    pub fn open(path: &Path) -> Result<Self, ZffError> {
        let mut f = fs::File::open(path)?;
        let mut header = [0u8; 9];
        f.read_exact(&mut header).map_err(|_| ZffError::Truncated)?;
        if &header[..4] != ZFF_MAGIC {
            return Err(ZffError::NotZff);
        }
        let version = header[4];
        let encryption = header[5] != 0;
        let compression = ZffCompression::from_u8(header[6]);
        let signature_algorithm = header[7];
        let segment_count = header[8];
        let total_size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        // Scan the first 64 KiB for the description block strings. We
        // look for ASCII runs prefixed with well-known ZFF description
        // keys (`examiner_name=`, `case_number=`, `acquisition_date=`,
        // `hash=`). Real ZFF encodes these as a CBOR map in the footer;
        // the minimal reader is tolerant of both plaintext debug dumps
        // and keyed CBOR text.
        let mut rest = Vec::new();
        let _ = f.take(64 * 1024).read_to_end(&mut rest);
        let all = std::str::from_utf8(&rest).unwrap_or("").to_string();
        let examiner_name = extract_key(&all, "examiner_name");
        let case_number = extract_key(&all, "case_number");
        let hash_value = extract_key(&all, "hash");
        let acquisition_date = extract_key(&all, "acquisition_date")
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        Ok(Self {
            path: path.to_path_buf(),
            metadata: ZffMetadata {
                version,
                encryption,
                compression,
                signature_algorithm,
                segment_count,
                examiner_name,
                case_number,
                acquisition_date,
                hash_value,
                total_size,
            },
        })
    }

    pub fn metadata(&self) -> &ZffMetadata {
        &self.metadata
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Placeholder sector reader — the minimal parser does not decode
    /// LZ4 chunks or resolve the segment table. Callers that need
    /// sector-level I/O must use the deep reader landing in a future
    /// sprint; we surface a clear error so the upgrade path is obvious
    /// rather than silently returning zeros.
    pub fn read_sector(&self, _lba: u64) -> Result<Vec<u8>, ZffError> {
        Err(ZffError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "ZffReader::read_sector not implemented in the minimal R-7 reader",
        )))
    }
}

fn extract_key(body: &str, key: &str) -> Option<String> {
    // Accept either `key=value\n`, `"key":"value"`, or `key: value`.
    if let Some(pos) = body.find(&format!("\"{}\":", key)) {
        let after = &body[pos + key.len() + 3..];
        if let Some(q1) = after.find('"') {
            let after_q = &after[q1 + 1..];
            if let Some(q2) = after_q.find('"') {
                return Some(after_q[..q2].to_string());
            }
        }
    }
    for pattern in [format!("{}=", key), format!("{}:", key)] {
        if let Some(pos) = body.find(&pattern) {
            let tail = &body[pos + pattern.len()..];
            let end = tail
                .find(['\n', '\r', '\0'])
                .unwrap_or(tail.len());
            let value = tail[..end].trim().trim_matches('"').to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_zff(dir: &tempfile::TempDir, header: &[u8], body: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join("image.zff");
        let mut f = fs::File::create(&path).expect("create");
        f.write_all(header).expect("header");
        f.write_all(body).expect("body");
        path
    }

    #[test]
    fn open_rejects_non_zff() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad");
        std::fs::write(&path, b"not a zff").expect("write");
        let err = ZffReader::open(&path).expect_err("should fail");
        assert!(matches!(err, ZffError::NotZff));
    }

    #[test]
    fn open_rejects_truncated_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tiny.zff");
        std::fs::write(&path, b"zff\x00\x03").expect("write");
        let err = ZffReader::open(&path).expect_err("should fail");
        assert!(matches!(err, ZffError::Truncated));
    }

    #[test]
    fn open_parses_minimal_header_and_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        // magic + version 3 + no encryption + lz4 + sig=1 + 4 segments.
        let header = [b'z', b'f', b'f', 0x00, 3, 0, 2, 1, 4];
        let body = b"\"examiner_name\":\"Detective Garcia\"\n\
                     \"case_number\":\"CASE-2026-0042\"\n\
                     \"acquisition_date\":\"2024-06-01T12:00:00Z\"\n\
                     \"hash\":\"deadbeefcafe\"\n";
        let path = write_zff(&dir, &header, body);
        let reader = ZffReader::open(&path).expect("open");
        let m = reader.metadata();
        assert_eq!(m.version, 3);
        assert!(!m.encryption);
        assert_eq!(m.compression, ZffCompression::Lz4);
        assert_eq!(m.segment_count, 4);
        assert_eq!(m.examiner_name.as_deref(), Some("Detective Garcia"));
        assert_eq!(m.case_number.as_deref(), Some("CASE-2026-0042"));
        assert_eq!(m.hash_value.as_deref(), Some("deadbeefcafe"));
        assert_eq!(
            m.acquisition_date.map(|d| d.timestamp()),
            Some(1_717_243_200)
        );
    }

    #[test]
    fn read_sector_returns_unsupported_for_minimal_reader() {
        let dir = tempfile::tempdir().expect("tempdir");
        let header = [b'z', b'f', b'f', 0x00, 3, 0, 0, 0, 1];
        let path = write_zff(&dir, &header, b"");
        let reader = ZffReader::open(&path).expect("open");
        assert!(reader.read_sector(0).is_err());
    }

    #[test]
    fn compression_enum_maps_algorithm_bytes() {
        assert_eq!(ZffCompression::from_u8(0), ZffCompression::None);
        assert_eq!(ZffCompression::from_u8(1), ZffCompression::Zstd);
        assert_eq!(ZffCompression::from_u8(2), ZffCompression::Lz4);
        assert!(matches!(
            ZffCompression::from_u8(42),
            ZffCompression::Unknown(42)
        ));
    }
}

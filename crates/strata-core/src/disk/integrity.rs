//! Evidence integrity verification (COC-2).
//!
//! Streaming hash computation over forensic images with sidecar-based
//! expected-hash lookup. Never loads the full image into memory.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;
use thiserror::Error;

const HASH_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum IntegrityError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("hash algorithm unsupported: {0}")]
    UnknownAlgo(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct IntegrityResult {
    pub image_path: String,
    pub expected_hash: Option<String>,
    pub computed_hash: String,
    pub hash_algorithm: String,
    pub verified: bool,
    pub sidecar_source: Option<String>,
    pub computation_duration_secs: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Md5,
    Sha1,
    Sha256,
}

impl HashAlgo {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgo::Md5 => "MD5",
            HashAlgo::Sha1 => "SHA1",
            HashAlgo::Sha256 => "SHA256",
        }
    }

    pub fn from_hex_len(hex_len: usize) -> Option<HashAlgo> {
        match hex_len {
            32 => Some(HashAlgo::Md5),
            40 => Some(HashAlgo::Sha1),
            64 => Some(HashAlgo::Sha256),
            _ => None,
        }
    }
}

/// Compute the hash of a file streaming in 64 KB chunks.
pub fn hash_file(path: &Path, algo: HashAlgo) -> Result<String, IntegrityError> {
    let f = fs::File::open(path)?;
    let mut reader = BufReader::with_capacity(HASH_CHUNK_BYTES, f);
    let mut buf = [0u8; HASH_CHUNK_BYTES];
    let hex = match algo {
        HashAlgo::Md5 => {
            let mut h = Md5::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            hex_of(&h.finalize())
        }
        HashAlgo::Sha1 => {
            let mut h = Sha1::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            hex_of(&h.finalize())
        }
        HashAlgo::Sha256 => {
            let mut h = Sha256::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            hex_of(&h.finalize())
        }
    };
    Ok(hex)
}

/// Find a sidecar hash file for `image_path`. Searches the 5 formats
/// listed in COC-2. Returns `(expected_hex, algo, sidecar_path)` on
/// success.
pub fn find_sidecar_hash(image_path: &Path) -> Option<(String, HashAlgo, PathBuf)> {
    let name = image_path.file_name()?.to_str()?;
    let dir = image_path.parent()?;
    for ext in ["md5", "sha256", "sha1"] {
        let candidate = dir.join(format!("{}.{}", name, ext));
        if let Ok(body) = fs::read_to_string(&candidate) {
            if let Some((hex, algo)) = parse_hash_line(&body, Some(ext)) {
                return Some((hex, algo, candidate));
            }
        }
    }
    // Generic .txt sidecar with Key: Value pairs.
    let txt = dir.join(format!("{}.txt", name));
    if let Ok(body) = fs::read_to_string(&txt) {
        if let Some((hex, algo)) = parse_hash_line(&body, None) {
            return Some((hex, algo, txt));
        }
    }
    // FTK Imager case summary.
    for candidate in fs::read_dir(dir).ok()?.flatten() {
        let p = candidate.path();
        if p.extension().and_then(|e| e.to_str()) != Some("txt") {
            continue;
        }
        if let Ok(body) = fs::read_to_string(&p) {
            if body.contains("MD5 checksum:") || body.contains("SHA1 checksum:") {
                if let Some((hex, algo)) = parse_ftk_summary(&body) {
                    return Some((hex, algo, p));
                }
            }
        }
    }
    None
}

fn parse_hash_line(body: &str, ext_hint: Option<&str>) -> Option<(String, HashAlgo)> {
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `<hex>  <filename>` form.
        if let Some((hex, _)) = line.split_once(char::is_whitespace) {
            let hex = hex.trim();
            if hex.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Some(algo) = HashAlgo::from_hex_len(hex.len()) {
                    if let Some(ext) = ext_hint {
                        if !matches_ext(algo, ext) {
                            continue;
                        }
                    }
                    return Some((hex.to_ascii_lowercase(), algo));
                }
            }
        }
        // `Key: Value` form.
        if let Some((key, value)) = line.split_once(':') {
            let key_lc = key.trim().to_ascii_lowercase();
            let value = value.trim();
            let algo = match key_lc.as_str() {
                "md5" | "md5:" | "md5 checksum" => Some(HashAlgo::Md5),
                "sha1" | "sha1:" | "sha1 checksum" => Some(HashAlgo::Sha1),
                "sha256" | "sha-256" | "sha256:" | "sha256 checksum" => Some(HashAlgo::Sha256),
                "hash" => HashAlgo::from_hex_len(value.len()),
                _ => None,
            };
            if let Some(algo) = algo {
                if value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some((value.to_ascii_lowercase(), algo));
                }
            }
        }
    }
    None
}

fn parse_ftk_summary(body: &str) -> Option<(String, HashAlgo)> {
    // Prefer SHA1 when both present; FTK classic reports use SHA1.
    for (key, algo) in [
        ("SHA256 checksum:", HashAlgo::Sha256),
        ("SHA1 checksum:", HashAlgo::Sha1),
        ("MD5 checksum:", HashAlgo::Md5),
    ] {
        if let Some(pos) = body.find(key) {
            let tail = &body[pos + key.len()..];
            let end = tail.find('\n').unwrap_or(tail.len());
            let v = tail[..end].trim();
            if v.chars().all(|c| c.is_ascii_hexdigit()) && !v.is_empty() {
                return Some((v.to_ascii_lowercase(), algo));
            }
        }
    }
    None
}

fn matches_ext(algo: HashAlgo, ext: &str) -> bool {
    matches!(
        (algo, ext),
        (HashAlgo::Md5, "md5") | (HashAlgo::Sha1, "sha1") | (HashAlgo::Sha256, "sha256")
    )
}

pub fn verify_image(path: &Path) -> Result<IntegrityResult, IntegrityError> {
    let sidecar = find_sidecar_hash(path);
    let (expected_hash, algo, sidecar_source) = match sidecar {
        Some((hex, algo, p)) => (
            Some(hex),
            algo,
            Some(p.to_string_lossy().to_string()),
        ),
        None => (None, HashAlgo::Sha256, None),
    };
    let started = Instant::now();
    let computed = hash_file(path, algo)?;
    let duration = started.elapsed().as_secs_f64();
    let verified = match &expected_hash {
        Some(expected) => expected.eq_ignore_ascii_case(&computed),
        None => false,
    };
    Ok(IntegrityResult {
        image_path: path.to_string_lossy().to_string(),
        expected_hash,
        computed_hash: computed,
        hash_algorithm: algo.as_str().to_string(),
        verified,
        sidecar_source,
        computation_duration_secs: duration,
    })
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &tempfile::TempDir, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.path().join(name);
        fs::write(&p, content).expect("w");
        p
    }

    #[test]
    fn hash_file_is_deterministic_and_hex() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write(&dir, "data.bin", b"hello strata");
        let h = hash_file(&p, HashAlgo::Sha256).expect("hash");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        let h2 = hash_file(&p, HashAlgo::Sha256).expect("hash");
        assert_eq!(h, h2, "SHA-256 must be deterministic");
        let q = write(&dir, "other.bin", b"different bytes");
        let h3 = hash_file(&q, HashAlgo::Sha256).expect("hash");
        assert_ne!(h, h3);
    }

    #[test]
    fn verify_image_matches_with_sidecar_md5() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image = write(&dir, "evidence.E01", b"evidence bytes");
        let expected = hash_file(&image, HashAlgo::Md5).expect("md5");
        write(
            &dir,
            "evidence.E01.md5",
            format!("{}  evidence.E01\n", expected).as_bytes(),
        );
        let result = verify_image(&image).expect("verify");
        assert!(result.verified);
        assert_eq!(result.hash_algorithm, "MD5");
    }

    #[test]
    fn verify_image_mismatch_reports_unverified() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image = write(&dir, "evidence.E01", b"evidence bytes");
        write(
            &dir,
            "evidence.E01.sha256",
            b"0000000000000000000000000000000000000000000000000000000000000000  evidence.E01\n",
        );
        let result = verify_image(&image).expect("verify");
        assert!(!result.verified);
        assert!(result.expected_hash.is_some());
    }

    #[test]
    fn verify_image_no_sidecar_records_computed_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image = write(&dir, "no_sidecar.E01", b"some bytes");
        let result = verify_image(&image).expect("verify");
        assert!(!result.verified);
        assert!(result.expected_hash.is_none());
        assert_eq!(result.hash_algorithm, "SHA256");
    }

    #[test]
    fn parse_ftk_summary_extracts_sha1_when_present() {
        let body = "Case: test\nMD5 checksum: aabbccdd\nSHA1 checksum: 1111111111111111111111111111111111111111\n";
        let (hex, algo) = parse_ftk_summary(body).expect("parse");
        assert_eq!(algo, HashAlgo::Sha1);
        assert_eq!(hex.len(), 40);
    }

    #[test]
    fn hash_algo_from_hex_len_correct() {
        assert_eq!(HashAlgo::from_hex_len(32), Some(HashAlgo::Md5));
        assert_eq!(HashAlgo::from_hex_len(40), Some(HashAlgo::Sha1));
        assert_eq!(HashAlgo::from_hex_len(64), Some(HashAlgo::Sha256));
        assert!(HashAlgo::from_hex_len(10).is_none());
    }
}

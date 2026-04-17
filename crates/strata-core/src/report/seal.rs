//! Cryptographic HTML report sealing via Ed25519 (UX-3).
//!
//! Signs the SHA-256 of the report HTML content (UTF-8 bytes before
//! the seal `<div>` is appended) so the signature covers only the
//! deterministic portion of the document.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;

pub const SEAL_VERSION: u32 = 1;
pub const SEAL_MARKER: &str = "<div id=\"strata-seal\"";

#[derive(Debug, Error)]
pub enum SealError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key bytes")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("report content has no seal block")]
    NoSeal,
    #[error("seal attribute missing: {0}")]
    Missing(&'static str),
    #[error("hex decode failed")]
    Hex,
    #[error("content hash mismatch (tampered)")]
    ContentHashMismatch,
    #[error("signature verification failed")]
    SignatureFailed,
}

/// Generate a fresh Ed25519 signing key.
pub fn generate_key() -> SigningKey {
    use rand::rngs::OsRng;
    SigningKey::generate(&mut OsRng)
}

pub fn encode_key(key: &SigningKey) -> String {
    hex_encode(&key.to_bytes())
}

pub fn decode_key(hex: &str) -> Result<SigningKey, SealError> {
    let bytes = hex_decode(hex).ok_or(SealError::Hex)?;
    if bytes.len() != 32 {
        return Err(SealError::InvalidKey);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&arr))
}

pub fn save_key(key: &SigningKey, path: &Path) -> Result<(), SealError> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    let pem = format!(
        "-----BEGIN STRATA ED25519 PRIVATE KEY-----\n{}\n-----END STRATA ED25519 PRIVATE KEY-----\n",
        encode_key(key)
    );
    fs::write(path, pem)?;
    Ok(())
}

pub fn load_key(path: &Path) -> Result<SigningKey, SealError> {
    let body = fs::read_to_string(path)?;
    let hex: String = body
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    decode_key(hex.trim())
}

/// Seal an HTML report. Returns the HTML with a trailing
/// `<div id="strata-seal">` appended.
pub fn seal_html(html: &str, key: &SigningKey) -> String {
    let timestamp: DateTime<Utc> = Utc::now();
    seal_html_with_timestamp(html, key, timestamp)
}

fn seal_html_with_timestamp(
    html: &str,
    key: &SigningKey,
    timestamp: DateTime<Utc>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(html.as_bytes());
    let digest = hasher.finalize();
    let signature = key.sign(&digest);
    let pubkey = key.verifying_key();
    let seal = format!(
        "<div id=\"strata-seal\" style=\"display:none\" \
         data-version=\"{}\" \
         data-timestamp=\"{}\" \
         data-examiner-pubkey=\"{}\" \
         data-signature=\"{}\" \
         data-content-hash=\"{}\"></div>\n",
        SEAL_VERSION,
        timestamp.to_rfc3339(),
        hex_encode(&pubkey.to_bytes()),
        hex_encode(&signature.to_bytes()),
        hex_encode(&digest),
    );
    let mut out = String::with_capacity(html.len() + seal.len() + 32);
    out.push_str(html);
    if !html.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&seal);
    out
}

/// Verify a sealed HTML report. Returns `Ok(SealVerification)` when
/// the signature is valid; `Err(SealError)` otherwise.
pub fn verify_sealed_html(sealed: &str) -> Result<SealVerification, SealError> {
    let seal_start = sealed
        .rfind(SEAL_MARKER)
        .ok_or(SealError::NoSeal)?;
    let content = &sealed[..seal_start];
    let content_trimmed = content.trim_end_matches('\n');
    let seal_end = sealed[seal_start..]
        .find("></div>")
        .ok_or(SealError::NoSeal)?;
    let seal_block = &sealed[seal_start..seal_start + seal_end];
    let pubkey_hex = extract_attr(seal_block, "data-examiner-pubkey")?;
    let signature_hex = extract_attr(seal_block, "data-signature")?;
    let content_hash_hex = extract_attr(seal_block, "data-content-hash")?;
    let timestamp_str = extract_attr(seal_block, "data-timestamp")?;
    let pubkey_bytes = hex_decode(&pubkey_hex).ok_or(SealError::Hex)?;
    let sig_bytes = hex_decode(&signature_hex).ok_or(SealError::Hex)?;
    let expected_hash = hex_decode(&content_hash_hex).ok_or(SealError::Hex)?;
    if pubkey_bytes.len() != 32 || sig_bytes.len() != 64 || expected_hash.len() != 32 {
        return Err(SealError::InvalidKey);
    }
    // Content hash check.
    let mut hasher = Sha256::new();
    // Re-hash the original content — must append trailing `\n` to
    // match what seal_html_with_timestamp signed.
    hasher.update(content_trimmed.as_bytes());
    let actual_hash = hasher.finalize();
    if actual_hash.as_slice() != expected_hash.as_slice() {
        return Err(SealError::ContentHashMismatch);
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pubkey_bytes);
    let verifying_key =
        VerifyingKey::from_bytes(&pk_arr).map_err(|_| SealError::InvalidKey)?;
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(&actual_hash, &signature)
        .map_err(|_| SealError::SignatureFailed)?;
    Ok(SealVerification {
        pubkey_hex,
        timestamp: timestamp_str,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealVerification {
    pub pubkey_hex: String,
    pub timestamp: String,
}

fn extract_attr(block: &str, attr: &'static str) -> Result<String, SealError> {
    let needle = format!("{}=\"", attr);
    let pos = block.find(&needle).ok_or(SealError::Missing(attr))?;
    let start = pos + needle.len();
    let end = block[start..]
        .find('"')
        .ok_or(SealError::Missing(attr))?;
    Ok(block[start..start + end].to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let key = generate_key();
        let html = "<html><body>test report</body></html>";
        let sealed = seal_html(html, &key);
        let result = verify_sealed_html(&sealed).expect("verified");
        assert_eq!(result.pubkey_hex, hex_encode(&key.verifying_key().to_bytes()));
    }

    #[test]
    fn tampered_content_fails_verification() {
        let key = generate_key();
        let html = "<html><body>original</body></html>";
        let sealed = seal_html(html, &key);
        // Tamper the body.
        let tampered = sealed.replace("original", "tampered");
        let result = verify_sealed_html(&tampered);
        assert!(result.is_err());
    }

    #[test]
    fn missing_seal_block_reports_nosseal_error() {
        let result = verify_sealed_html("<html>no seal here</html>");
        assert!(matches!(result, Err(SealError::NoSeal)));
    }

    #[test]
    fn key_save_and_load_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("examiner.key");
        let key = generate_key();
        save_key(&key, &path).expect("save");
        let loaded = load_key(&path).expect("load");
        assert_eq!(loaded.to_bytes(), key.to_bytes());
    }

    #[test]
    fn hex_encode_decode_round_trip() {
        let original = b"\x01\x02\x03\xDE\xAD\xBE\xEF";
        let enc = hex_encode(original);
        let dec = hex_decode(&enc).expect("decode");
        assert_eq!(dec, original);
    }

    #[test]
    fn decode_key_rejects_wrong_length() {
        assert!(matches!(decode_key("aabb"), Err(SealError::InvalidKey)));
    }
}

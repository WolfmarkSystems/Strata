//! VeraCrypt / TrueCrypt detection (VAULT-2).
//!
//! VeraCrypt volumes have no fixed magic by design (deniability). We
//! surface candidates via a combination of sector-aligned size, absent
//! common-file-magic, and near-maximum entropy in the first 512 bytes.
//!
//! MITRE: T1027.013 (encrypted/encoded file), T1553 (subvert trust).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use std::fs;
use std::io::Read;
use std::path::Path;
use strata_plugin_sdk::Artifact;

const MIN_VOLUME_SIZE: u64 = 2 * 1024 * 1024;
const ENTROPY_THRESHOLD: f64 = 7.9;
const HEAD_SAMPLE: usize = 512;

/// Typed artifact for downstream consumers that want the structured
/// fields; the plugin-facing layer emits `Artifact::new(...)`.
#[derive(Debug, Clone, PartialEq)]
pub struct VeraCryptArtifact {
    pub detection_method: String,
    pub path: String,
    pub entropy: Option<f64>,
    pub file_size: Option<u64>,
    pub last_mount: Option<String>,
    pub keyfiles: Vec<String>,
    pub history: Vec<String>,
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let mut out = Vec::new();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // 1. VeraCrypt preferences file.
    if name == "veracrypt.xml" {
        if let Some(a) = parse_preferences(path) {
            out.push(a);
        }
        return out;
    }
    // 2. Volume candidates by extension or by entropy + size heuristic.
    let ext = name.rsplit('.').next().unwrap_or("");
    let suggests_volume = matches!(ext, "vc" | "hc" | "tc");
    let Ok(meta) = fs::metadata(path) else {
        return out;
    };
    if !meta.is_file() {
        return out;
    }
    let size = meta.len();
    if size < MIN_VOLUME_SIZE || size % 512 != 0 {
        return out;
    }
    let Ok(mut f) = fs::File::open(path) else {
        return out;
    };
    let mut head = vec![0u8; HEAD_SAMPLE];
    let Ok(_) = f.read_exact(&mut head) else {
        return out;
    };
    if has_known_magic(&head) && !suggests_volume {
        return out;
    }
    let entropy = shannon_entropy(&head);
    if !(suggests_volume || entropy > ENTROPY_THRESHOLD) {
        return out;
    }
    let path_str = path.to_string_lossy().to_string();
    let method = if suggests_volume {
        "extension+entropy"
    } else {
        "entropy"
    };
    let mut a = Artifact::new("VeraCrypt Volume", &path_str);
    a.add_field("title", &format!("Suspected VeraCrypt volume: {}", name));
    a.add_field(
        "detail",
        &format!(
            "Path: {} | size: {} bytes | first-512 entropy: {:.4} | detection: {}",
            path_str, size, entropy, method
        ),
    );
    a.add_field("file_type", "VeraCrypt Volume");
    a.add_field("detection_method", method);
    a.add_field("entropy", &format!("{:.4}", entropy));
    a.add_field("file_size", &size.to_string());
    a.add_field("mitre", "T1027.013");
    a.add_field("mitre_secondary", "T1553");
    a.add_field("forensic_value", "High");
    a.add_field("suspicious", "true");
    out.push(a);
    out
}

fn has_known_magic(head: &[u8]) -> bool {
    // Conservative list of common file headers — any match means this
    // file is NOT a VeraCrypt volume, regardless of entropy.
    const MAGICS: &[&[u8]] = &[
        b"\x89PNG",
        b"GIF8",
        b"%PDF",
        b"PK\x03\x04",
        b"Rar!\x1A\x07",
        b"7z\xBC\xAF\x27\x1C",
        b"SQLite format 3\0",
        b"\x7FELF",
        b"MZ",
        b"\xFF\xD8\xFF",
        b"ftyp",
    ];
    for m in MAGICS {
        if head.len() >= m.len() && &head[..m.len()] == *m {
            return true;
        }
    }
    false
}

fn parse_preferences(path: &Path) -> Option<Artifact> {
    let body = fs::read_to_string(path).ok()?;
    let last_used_volume_path = extract_tag(&body, "LastUsedVolumePath");
    let history = extract_list(&body, "HistoryEntry");
    let keyfiles = extract_list(&body, "Keyfile");
    let path_str = path.to_string_lossy().to_string();
    let mut a = Artifact::new("VeraCrypt Preferences", &path_str);
    a.add_field("title", "VeraCrypt preferences (VeraCrypt.xml)");
    a.add_field(
        "detail",
        &format!(
            "last_volume: {} | history_entries: {} | keyfiles: {}",
            last_used_volume_path.as_deref().unwrap_or("-"),
            history.len(),
            keyfiles.len()
        ),
    );
    a.add_field("file_type", "VeraCrypt Preferences");
    if let Some(v) = &last_used_volume_path {
        a.add_field("last_mount", v);
    }
    for (i, h) in history.iter().enumerate() {
        a.add_field("history", h);
        if i >= 32 {
            break;
        }
    }
    for k in &keyfiles {
        a.add_field("keyfile", k);
    }
    a.add_field("mitre", "T1027.013");
    a.add_field("forensic_value", "High");
    a.add_field("suspicious", "true");
    Some(a)
}

fn extract_tag(body: &str, name: &str) -> Option<String> {
    let open = format!("<{}>", name);
    let close = format!("</{}>", name);
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)?;
    Some(body[start..start + end].trim().to_string())
}

fn extract_list(body: &str, name: &str) -> Vec<String> {
    let open = format!("<{}>", name);
    let close = format!("</{}>", name);
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(s_rel) = body[cursor..].find(&open) {
        let s = cursor + s_rel + open.len();
        let Some(e_rel) = body[s..].find(&close) else {
            break;
        };
        out.push(body[s..s + e_rel].trim().to_string());
        cursor = s + e_rel + close.len();
    }
    out
}

/// Shannon entropy in bits/byte.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        h -= p * p.log2();
    }
    h
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        let uniform: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&uniform) - 8.0).abs() < 0.001);
    }

    #[test]
    fn scan_flags_high_entropy_sector_aligned_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("volume.vc");
        // 2 MB of pseudo-random bytes.
        let mut bytes = Vec::with_capacity(MIN_VOLUME_SIZE as usize);
        let mut x: u64 = 0xDEAD_BEEF_1234_5678;
        for _ in 0..MIN_VOLUME_SIZE {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            bytes.push((x & 0xFF) as u8);
        }
        std::fs::write(&path, &bytes).expect("write");
        let out = scan(&path);
        assert!(out.iter().any(|a| a.data.get("file_type").map(|s| s.as_str()) == Some("VeraCrypt Volume")));
    }

    #[test]
    fn scan_ignores_known_magic_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("image.jpg");
        let mut body = vec![0xFF, 0xD8, 0xFF, 0xE0];
        body.resize(MIN_VOLUME_SIZE as usize, 0);
        std::fs::write(&path, &body).expect("write");
        assert!(scan(&path).is_empty());
    }

    #[test]
    fn scan_parses_veracrypt_preferences() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("VeraCrypt.xml");
        std::fs::write(
            &path,
            "<VeraCrypt>\n  <LastUsedVolumePath>C:\\secret.vc</LastUsedVolumePath>\n  <HistoryEntry>C:\\secret.vc</HistoryEntry>\n  <HistoryEntry>D:\\images.hc</HistoryEntry>\n  <Keyfile>C:\\keys\\key.key</Keyfile>\n</VeraCrypt>\n",
        )
        .expect("write");
        let out = scan(&path);
        assert_eq!(out.len(), 1);
        let a = &out[0];
        assert_eq!(
            a.data.get("file_type").map(|s| s.as_str()),
            Some("VeraCrypt Preferences")
        );
        assert_eq!(a.data.get("last_mount").map(|s| s.as_str()), Some("C:\\secret.vc"));
    }

    #[test]
    fn scan_ignores_small_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("small.vc");
        std::fs::write(&path, b"small").expect("write");
        assert!(scan(&path).is_empty());
    }
}

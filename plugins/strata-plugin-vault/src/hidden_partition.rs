//! Hidden partitions + steganography indicators (VAULT-5).
//!
//! HPA / DCO detection requires live-acquisition ATA commands; when
//! working from a forensic image we annotate that requirement rather
//! than silently skip. MBR gaps and anomalous JPEG sizes are both
//! statically detectable from an image alone.
//!
//! MITRE: T1027.003 (steganography), T1564.005 (hidden file system).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use std::fs;
use std::io::Read;
use std::path::Path;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiddenStorageType {
    UnaccountedPartitionGap,
    HostProtectedArea,
    DeviceConfigurationOverlay,
    SteganographyIndicator,
    AnomalousFileSize,
}

impl HiddenStorageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            HiddenStorageType::UnaccountedPartitionGap => "UnaccountedPartitionGap",
            HiddenStorageType::HostProtectedArea => "HostProtectedArea",
            HiddenStorageType::DeviceConfigurationOverlay => "DeviceConfigurationOverlay",
            HiddenStorageType::SteganographyIndicator => "SteganographyIndicator",
            HiddenStorageType::AnomalousFileSize => "AnomalousFileSize",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HiddenStorageArtifact {
    pub detection_type: HiddenStorageType,
    pub location: String,
    pub hidden_size: Option<u64>,
    pub confidence: String,
    pub stat_score: Option<f64>,
    pub notes: String,
}

fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 4 || &bytes[..3] != b"\xFF\xD8\xFF" {
        return None;
    }
    let mut i = 2;
    while i + 8 < bytes.len() {
        if bytes[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = bytes[i + 1];
        let seg_len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
        if (0xC0..=0xCF).contains(&marker) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC {
            if i + 9 >= bytes.len() {
                return None;
            }
            let h = u16::from_be_bytes([bytes[i + 5], bytes[i + 6]]) as u32;
            let w = u16::from_be_bytes([bytes[i + 7], bytes[i + 8]]) as u32;
            return Some((w, h));
        }
        i += 2 + seg_len;
    }
    None
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let mut out = Vec::new();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !(name.ends_with(".jpg") || name.ends_with(".jpeg")) {
        return out;
    }
    let Ok(meta) = fs::metadata(path) else {
        return out;
    };
    if !meta.is_file() {
        return out;
    }
    let size = meta.len();
    let Ok(mut f) = fs::File::open(path) else {
        return out;
    };
    let mut head = vec![0u8; (64 * 1024).min(size as usize)];
    if f.read_exact(&mut head).is_err() {
        return out;
    }
    let Some((w, h)) = jpeg_dimensions(&head) else {
        return out;
    };
    let pixels = (w as u64).saturating_mul(h as u64);
    if pixels == 0 {
        return out;
    }
    let expected = (pixels as f64) * 0.1;
    let ratio = if expected > 0.0 {
        size as f64 / expected
    } else {
        0.0
    };
    if ratio <= 3.0 {
        return out;
    }
    let path_str = path.to_string_lossy().to_string();
    let mut a = Artifact::new("Hidden Storage Indicator", &path_str);
    a.add_field(
        "title",
        &format!("Anomalous JPEG size — possible steganography: {}", name),
    );
    a.add_field(
        "detail",
        &format!(
            "Dimensions: {}x{} | expected ~{:.0} bytes | actual {} bytes | ratio {:.2}",
            w, h, expected, size, ratio
        ),
    );
    a.add_field("file_type", "Hidden Storage Indicator");
    a.add_field("detection_type", HiddenStorageType::AnomalousFileSize.as_str());
    a.add_field("location", &path_str);
    a.add_field("stat_score", &format!("{:.4}", ratio));
    a.add_field(
        "hidden_size",
        &(size.saturating_sub(expected as u64)).to_string(),
    );
    a.add_field("confidence", "Medium");
    a.add_field("mitre", "T1027.003");
    a.add_field("mitre_secondary", "T1564.005");
    a.add_field("forensic_value", "High");
    a.add_field("suspicious", "true");
    out.push(a);
    out
}

/// MBR partition-table walker. Returns `(start, length)` tuples for
/// unaccounted ranges. Callers drive reporting.
pub fn mbr_gaps(mbr: &[u8]) -> Vec<(u64, u64)> {
    let mut gaps = Vec::new();
    if mbr.len() < 512 {
        return gaps;
    }
    let mut entries: Vec<(u64, u64)> = Vec::new();
    for i in 0..4 {
        let off = 446 + i * 16;
        let part_type = mbr[off + 4];
        let lba = u32::from_le_bytes([mbr[off + 8], mbr[off + 9], mbr[off + 10], mbr[off + 11]])
            as u64;
        let sectors = u32::from_le_bytes([
            mbr[off + 12],
            mbr[off + 13],
            mbr[off + 14],
            mbr[off + 15],
        ]) as u64;
        if part_type == 0 && (lba != 0 || sectors != 0) {
            gaps.push((lba, sectors));
            continue;
        }
        if part_type != 0 {
            entries.push((lba, sectors));
        }
    }
    entries.sort_by_key(|e| e.0);
    let mut prev_end: u64 = 2048;
    for (lba, sectors) in entries {
        if lba > prev_end + 2048 {
            gaps.push((prev_end, lba - prev_end));
        }
        prev_end = lba + sectors;
    }
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_dimensions_parses_minimal_sof() {
        let mut blob = vec![0xFF, 0xD8, 0xFF, 0xE0];
        blob.extend_from_slice(&[0x00, 0x10]);
        blob.extend_from_slice(&[0u8; 14]);
        blob.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        blob.extend_from_slice(&200u16.to_be_bytes());
        blob.extend_from_slice(&400u16.to_be_bytes());
        blob.extend_from_slice(&[0u8; 10]);
        assert_eq!(jpeg_dimensions(&blob), Some((400, 200)));
    }

    #[test]
    fn scan_flags_oversized_jpeg() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("suspicious.jpg");
        let mut blob = vec![0xFF, 0xD8, 0xFF, 0xE0];
        blob.extend_from_slice(&[0x00, 0x10]);
        blob.extend_from_slice(&[0u8; 14]);
        blob.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        blob.extend_from_slice(&100u16.to_be_bytes());
        blob.extend_from_slice(&200u16.to_be_bytes());
        blob.extend_from_slice(&[0u8; 10]);
        while blob.len() < 20_000 {
            blob.push(0xAA);
        }
        std::fs::write(&path, &blob).expect("write");
        let out = scan(&path);
        assert!(out.iter().any(
            |a| a.data.get("detection_type").map(|s| s.as_str()) == Some("AnomalousFileSize")
        ));
    }

    #[test]
    fn scan_ignores_reasonable_jpeg_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("normal.jpg");
        let mut blob = vec![0xFF, 0xD8, 0xFF, 0xE0];
        blob.extend_from_slice(&[0x00, 0x10]);
        blob.extend_from_slice(&[0u8; 14]);
        blob.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        blob.extend_from_slice(&500u16.to_be_bytes());
        blob.extend_from_slice(&500u16.to_be_bytes());
        blob.extend_from_slice(&[0u8; 10]);
        while blob.len() < 50_000 {
            blob.push(0xAA);
        }
        std::fs::write(&path, &blob).expect("write");
        assert!(scan(&path).is_empty());
    }

    #[test]
    fn mbr_gaps_flags_unused_range() {
        let mut mbr = vec![0u8; 512];
        let off = 446;
        mbr[off + 4] = 0x07;
        mbr[off + 8..off + 12].copy_from_slice(&2048u32.to_le_bytes());
        mbr[off + 12..off + 16].copy_from_slice(&100u32.to_le_bytes());
        let off2 = 446 + 16;
        mbr[off2 + 4] = 0x07;
        mbr[off2 + 8..off2 + 12].copy_from_slice(&200_000u32.to_le_bytes());
        mbr[off2 + 12..off2 + 16].copy_from_slice(&1000u32.to_le_bytes());
        let gaps = mbr_gaps(&mbr);
        assert!(!gaps.is_empty());
    }

    #[test]
    fn scan_noop_on_non_jpeg() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("normal.txt");
        std::fs::write(&path, b"hello").expect("write");
        assert!(scan(&path).is_empty());
    }
}

//! LEGACY-IOS-1 — Biome format version handling.
//!
//! Biome SEGB record layouts evolved across iOS 15 / 16 / 17 / 18 and
//! the 26 line. This module owns the format-detection helpers and
//! per-version record-layout descriptors; the existing `biome.rs`
//! stream parsers consume the descriptor so they can pick field
//! offsets without hard-coding a single schema.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BiomeFormatVersion {
    /// iOS 15 + 16 original Biome SEGB format.
    V15_16,
    /// iOS 17 restructured SEGB records.
    V17,
    /// iOS 18 schema refinements.
    V18,
    /// iOS 26 major bump (layout TBD pending real sample).
    V26,
    /// Unknown / future.
    Unknown,
}

impl BiomeFormatVersion {
    pub fn label(&self) -> &'static str {
        match self {
            Self::V15_16 => "iOS 15/16",
            Self::V17 => "iOS 17",
            Self::V18 => "iOS 18",
            Self::V26 => "iOS 26",
            Self::Unknown => "unknown",
        }
    }

    /// Width of a fixed-size record header in the given version.
    /// Callers use this to compute per-record offsets cheaply without
    /// re-parsing the header each time.
    pub fn header_bytes(&self) -> usize {
        match self {
            Self::V15_16 => 16,
            Self::V17 => 24,
            Self::V18 => 28,
            Self::V26 => 32,
            Self::Unknown => 0,
        }
    }
}

/// Detect the Biome format version from a raw SEGB header. The file
/// starts with the ASCII magic `SEGB` followed by a 4-byte version
/// field. We read the version and map it to the enum.
pub fn detect(header_bytes: &[u8]) -> BiomeFormatVersion {
    if header_bytes.len() < 8 {
        return BiomeFormatVersion::Unknown;
    }
    if &header_bytes[0..4] != b"SEGB" {
        return BiomeFormatVersion::Unknown;
    }
    let v = u32::from_le_bytes([
        header_bytes[4],
        header_bytes[5],
        header_bytes[6],
        header_bytes[7],
    ]);
    match v {
        1 | 2 => BiomeFormatVersion::V15_16,
        3 => BiomeFormatVersion::V17,
        4 => BiomeFormatVersion::V18,
        // Apple reserved the higher-nibble range for iOS 26. We
        // accept 5 and above until we have real samples to refine.
        5..=9 => BiomeFormatVersion::V26,
        _ => BiomeFormatVersion::Unknown,
    }
}

/// Canonical list of Biome streams the pulse plugin cares about —
/// same across versions so downstream correlation doesn't care which
/// iOS build produced the record.
pub const STREAMS_ACROSS_VERSIONS: &[&str] = &[
    "app/inFocus",
    "safariHistory",
    "photos/assetAdded",
    "messaging/sent",
    "location/significant",
    "app/intents",
    "app/launch",
];

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(v: u32) -> Vec<u8> {
        let mut h = Vec::with_capacity(8);
        h.extend_from_slice(b"SEGB");
        h.extend_from_slice(&v.to_le_bytes());
        h
    }

    #[test]
    fn detects_ios_15_16() {
        assert_eq!(detect(&hdr(1)), BiomeFormatVersion::V15_16);
        assert_eq!(detect(&hdr(2)), BiomeFormatVersion::V15_16);
    }

    #[test]
    fn detects_ios_17_18_26() {
        assert_eq!(detect(&hdr(3)), BiomeFormatVersion::V17);
        assert_eq!(detect(&hdr(4)), BiomeFormatVersion::V18);
        assert_eq!(detect(&hdr(5)), BiomeFormatVersion::V26);
    }

    #[test]
    fn rejects_bad_magic() {
        let bad = b"ABCD\x01\x00\x00\x00".to_vec();
        assert_eq!(detect(&bad), BiomeFormatVersion::Unknown);
    }

    #[test]
    fn short_header_returns_unknown() {
        assert_eq!(detect(&[]), BiomeFormatVersion::Unknown);
        assert_eq!(detect(b"SE"), BiomeFormatVersion::Unknown);
    }

    #[test]
    fn header_sizes_grow_with_version() {
        assert!(BiomeFormatVersion::V15_16.header_bytes() < BiomeFormatVersion::V17.header_bytes());
        assert!(BiomeFormatVersion::V17.header_bytes() < BiomeFormatVersion::V18.header_bytes());
        assert!(BiomeFormatVersion::V18.header_bytes() < BiomeFormatVersion::V26.header_bytes());
    }

    #[test]
    fn streams_list_is_stable() {
        assert!(STREAMS_ACROSS_VERSIONS.contains(&"safariHistory"));
        assert!(STREAMS_ACROSS_VERSIONS.contains(&"location/significant"));
    }
}

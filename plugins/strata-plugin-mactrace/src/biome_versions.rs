//! LEGACY-MAC-1 — macOS Biome evolution across Ventura / Sonoma /
//! Sequoia / Tahoe.
//!
//! Owns the version-detection helpers and the per-version stream
//! inventory. Plugin callers use this to decide which stream
//! parsers to run against a given disk image. The unified output
//! shape (`MacOSBiomeEvent`) lets downstream correlation ignore
//! which macOS build produced a record.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacOSVersion {
    /// Monterey (12) — no Biome, pre-sprint code path.
    Monterey,
    /// Ventura (13) — Biome introduced.
    Ventura,
    /// Sonoma (14) — networkUsage, deviceLocked, new photo schema.
    Sonoma,
    /// Sequoia (15) — Apple Intelligence precursor streams.
    Sequoia,
    /// Tahoe (26) — major Apple Intelligence + clipboard additions.
    Tahoe,
    Unknown,
}

impl MacOSVersion {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Monterey => "macOS Monterey (12)",
            Self::Ventura => "macOS Ventura (13)",
            Self::Sonoma => "macOS Sonoma (14)",
            Self::Sequoia => "macOS Sequoia (15)",
            Self::Tahoe => "macOS Tahoe (26)",
            Self::Unknown => "macOS (unknown)",
        }
    }

    /// Does this version support Biome at all?
    pub fn has_biome(&self) -> bool {
        !matches!(self, Self::Monterey | Self::Unknown)
    }

    /// Ordered list of Biome streams present in this version.
    pub fn streams(&self) -> &'static [&'static str] {
        match self {
            Self::Monterey | Self::Unknown => &[],
            Self::Ventura => &[
                "app/inFocus",
                "app/intents",
                "app/launch",
                "safariHistory",
                "notifications",
                "mediaPlayback",
            ],
            Self::Sonoma => &[
                "app/inFocus",
                "app/intents",
                "app/launch",
                "safariHistory",
                "notifications",
                "mediaPlayback",
                "networkUsage",
                "locationActivity",
                "deviceLocked",
                "photos/assetAdded",
            ],
            Self::Sequoia => &[
                "app/inFocus",
                "app/intents",
                "app/launch",
                "safariHistory",
                "notifications",
                "mediaPlayback",
                "networkUsage",
                "locationActivity",
                "deviceLocked",
                "photos/assetAdded",
                "appleIntelligence/requests",
            ],
            Self::Tahoe => &[
                "app/inFocus",
                "app/intents",
                "app/launch",
                "safariHistory",
                "notifications",
                "mediaPlayback",
                "networkUsage",
                "locationActivity",
                "deviceLocked",
                "photos/assetAdded",
                "appleIntelligence/requests",
                "clipboard/entry",
                "writingTools/applied",
            ],
        }
    }
}

/// Parse a `ProductVersion` string (e.g. "13.6.1", "14.4", "15.2",
/// "26.1") into a `MacOSVersion` enum.
pub fn parse_product_version(s: &str) -> MacOSVersion {
    let major = s.split('.').next().unwrap_or("");
    match major.parse::<u32>() {
        Ok(12) => MacOSVersion::Monterey,
        Ok(13) => MacOSVersion::Ventura,
        Ok(14) => MacOSVersion::Sonoma,
        Ok(15) => MacOSVersion::Sequoia,
        Ok(v) if (16..=26).contains(&v) => MacOSVersion::Tahoe,
        _ => MacOSVersion::Unknown,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MacOSBiomeEvent {
    pub stream_type: String,
    pub timestamp: DateTime<Utc>,
    pub source_app: Option<String>,
    pub event_data: HashMap<String, String>,
    pub macos_version: String,
    pub biome_format_version: String,
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parser_maps_majors() {
        assert_eq!(parse_product_version("13.6.1"), MacOSVersion::Ventura);
        assert_eq!(parse_product_version("14.4"), MacOSVersion::Sonoma);
        assert_eq!(parse_product_version("15.0"), MacOSVersion::Sequoia);
        assert_eq!(parse_product_version("26.1"), MacOSVersion::Tahoe);
        assert_eq!(parse_product_version("12.0"), MacOSVersion::Monterey);
        assert_eq!(parse_product_version("garbage"), MacOSVersion::Unknown);
    }

    #[test]
    fn monterey_has_no_biome() {
        assert!(!MacOSVersion::Monterey.has_biome());
        assert!(MacOSVersion::Ventura.has_biome());
        assert!(MacOSVersion::Tahoe.has_biome());
    }

    #[test]
    fn sonoma_streams_include_network_usage() {
        assert!(MacOSVersion::Sonoma.streams().contains(&"networkUsage"));
        // Ventura did not have it.
        assert!(!MacOSVersion::Ventura.streams().contains(&"networkUsage"));
    }

    #[test]
    fn sequoia_adds_apple_intelligence_stream() {
        assert!(MacOSVersion::Sequoia
            .streams()
            .contains(&"appleIntelligence/requests"));
    }

    #[test]
    fn tahoe_adds_clipboard_and_writing_tools_streams() {
        let s = MacOSVersion::Tahoe.streams();
        assert!(s.contains(&"clipboard/entry"));
        assert!(s.contains(&"writingTools/applied"));
    }

    #[test]
    fn unified_event_shape_roundtrips_serde() {
        let mut data = HashMap::new();
        data.insert("bundle_id".into(), "com.apple.Safari".into());
        let e = MacOSBiomeEvent {
            stream_type: "safariHistory".into(),
            timestamp: Utc::now(),
            source_app: Some("Safari".into()),
            event_data: data,
            macos_version: "Sonoma".into(),
            biome_format_version: "v2".into(),
        };
        let s = serde_json::to_string(&e).expect("ser");
        let e2: MacOSBiomeEvent = serde_json::from_str(&s).expect("de");
        assert_eq!(e.stream_type, e2.stream_type);
    }
}

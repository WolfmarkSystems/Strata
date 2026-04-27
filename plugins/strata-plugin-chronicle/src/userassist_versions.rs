//! LEGACY-WIN-3 — Windows 10 vs 11 format variants.
//!
//! Small, surgical helpers for version-aware format dispatch:
//! ShimCache, AmCache, UserAssist, registry-transaction-log, and
//! Prefetch. Each helper takes a magic-byte / version-byte slice and
//! returns the detected `WindowsVersion`; each parser can then
//! branch cleanly instead of re-deriving the version from context.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowsVersion {
    XP,
    Win7,
    Win8,
    Win10,
    Win11,
    Unknown,
}

impl WindowsVersion {
    pub fn label(&self) -> &'static str {
        match self {
            Self::XP => "Windows XP",
            Self::Win7 => "Windows 7",
            Self::Win8 => "Windows 8/8.1",
            Self::Win10 => "Windows 10",
            Self::Win11 => "Windows 11",
            Self::Unknown => "Windows (unknown)",
        }
    }
}

/// ShimCache version dispatch. Signatures from the
/// AppCompatibility/AppCompatCache header.
pub fn shimcache_version(bytes: &[u8]) -> WindowsVersion {
    if bytes.len() < 4 {
        return WindowsVersion::Unknown;
    }
    let sig = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    match sig {
        0xBADC0FEE => WindowsVersion::Win7, // v2 (Win7)
        0xBADC0FFE => WindowsVersion::Win8, // v3 (Win8/8.1)
        0x30 => WindowsVersion::Win10,      // v4 (Win10)
        0x34 => WindowsVersion::Win11,      // v5 (Win11)
        _ => WindowsVersion::Unknown,
    }
}

/// Prefetch format-version -> Windows version.
pub fn prefetch_version(prefetch_version: u32) -> WindowsVersion {
    match prefetch_version {
        17 => WindowsVersion::XP,
        23 => WindowsVersion::Win7,
        26 | 30 => WindowsVersion::Win10,
        31 => WindowsVersion::Win11,
        _ => WindowsVersion::Unknown,
    }
}

/// Registry transaction-log dispatch (by file-suffix convention).
pub fn transaction_log_kind(filename: &str) -> TransactionLogKind {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".log1") || lower.ends_with(".log2") {
        TransactionLogKind::Modern
    } else if lower.ends_with(".log") {
        TransactionLogKind::Legacy
    } else {
        TransactionLogKind::None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionLogKind {
    Legacy,
    Modern,
    None,
}

/// UserAssist GUID bucket -> Windows version (helps the decoder
/// apply the right field layout).
pub fn userassist_bucket_version(guid: &str) -> WindowsVersion {
    let g = guid
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_ascii_uppercase();
    match g.as_str() {
        "75048700-EF1F-11D0-9888-006097DEACF9" => WindowsVersion::XP,
        "5E6AB780-7743-11CF-A12B-00AA004AE837" => WindowsVersion::XP,
        "CEBFF5CD-ACE2-4F4F-9178-9926F41749EA" => WindowsVersion::Win7,
        "F4E57C4B-2036-45F0-A9AB-443BCFE33D9F" => WindowsVersion::Win7,
        "9E04CAB2-CC14-11DF-BB8C-A2F1DED72085" => WindowsVersion::Win10,
        _ => WindowsVersion::Unknown,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shimcache_sig_dispatch() {
        let buf = 0xBADC0FEEu32.to_le_bytes();
        assert_eq!(shimcache_version(&buf), WindowsVersion::Win7);
        let buf = 0x30u32.to_le_bytes();
        assert_eq!(shimcache_version(&buf), WindowsVersion::Win10);
    }

    #[test]
    fn prefetch_version_maps_known_numbers() {
        assert_eq!(prefetch_version(17), WindowsVersion::XP);
        assert_eq!(prefetch_version(23), WindowsVersion::Win7);
        assert_eq!(prefetch_version(30), WindowsVersion::Win10);
        assert_eq!(prefetch_version(31), WindowsVersion::Win11);
        assert_eq!(prefetch_version(999), WindowsVersion::Unknown);
    }

    #[test]
    fn transaction_log_kind_recognises_suffixes() {
        assert_eq!(
            transaction_log_kind("SYSTEM.LOG1"),
            TransactionLogKind::Modern
        );
        assert_eq!(
            transaction_log_kind("system.log"),
            TransactionLogKind::Legacy
        );
        assert_eq!(transaction_log_kind("system"), TransactionLogKind::None);
    }

    #[test]
    fn userassist_bucket_lookup() {
        assert_eq!(
            userassist_bucket_version("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"),
            WindowsVersion::Win7
        );
        assert_eq!(
            userassist_bucket_version("{unknown-guid}"),
            WindowsVersion::Unknown
        );
    }

    #[test]
    fn label_is_stable() {
        assert_eq!(WindowsVersion::Win11.label(), "Windows 11");
    }
}

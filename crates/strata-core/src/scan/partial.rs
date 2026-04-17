//! Partial image scan configuration (FIELD-1).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanRegion {
    FromStart,
    FromEnd,
    Both,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartialScanConfig {
    pub max_bytes: u64,
    pub scan_region: ScanRegion,
    pub plugins: Vec<String>,
}

impl Default for PartialScanConfig {
    fn default() -> Self {
        Self {
            max_bytes: 0,
            scan_region: ScanRegion::FromStart,
            plugins: Vec::new(),
        }
    }
}

impl PartialScanConfig {
    pub fn is_partial(&self) -> bool {
        self.max_bytes > 0
    }

    /// Returns `(start, length)` byte offsets to scan given total
    /// image size. `length` is capped at `max_bytes`.
    pub fn regions(&self, image_size: u64) -> Vec<(u64, u64)> {
        if !self.is_partial() || image_size == 0 {
            return vec![(0, image_size)];
        }
        let cap = self.max_bytes.min(image_size);
        match self.scan_region {
            ScanRegion::FromStart => vec![(0, cap)],
            ScanRegion::FromEnd => {
                let start = image_size.saturating_sub(cap);
                vec![(start, cap)]
            }
            ScanRegion::Both => {
                let half = cap / 2;
                let tail_start = image_size.saturating_sub(half);
                if tail_start <= half {
                    vec![(0, image_size)]
                } else {
                    vec![(0, half), (tail_start, half)]
                }
            }
        }
    }

    pub fn caveat(&self, image_size: u64) -> Option<String> {
        if !self.is_partial() {
            return None;
        }
        Some(format!(
            "PARTIAL SCAN: Only {} of {} bytes examined (region: {:?}). \
             Findings are incomplete. Full examination required for evidentiary use.",
            self.max_bytes.min(image_size),
            image_size,
            self.scan_region
        ))
    }
}

/// Plugins that declare partial-scan support.
pub fn supports_partial_scan(plugin: &str) -> bool {
    matches!(
        plugin,
        "phantom"
            | "Strata Phantom"
            | "trace"
            | "Strata Trace"
            | "chronicle"
            | "Strata Chronicle"
            | "carbon"
            | "Strata Carbon"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_start_region_produces_single_prefix() {
        let cfg = PartialScanConfig {
            max_bytes: 1_000,
            scan_region: ScanRegion::FromStart,
            plugins: Vec::new(),
        };
        let regions = cfg.regions(10_000);
        assert_eq!(regions, vec![(0, 1_000)]);
    }

    #[test]
    fn from_end_region_produces_suffix() {
        let cfg = PartialScanConfig {
            max_bytes: 1_000,
            scan_region: ScanRegion::FromEnd,
            plugins: Vec::new(),
        };
        let regions = cfg.regions(10_000);
        assert_eq!(regions, vec![(9_000, 1_000)]);
    }

    #[test]
    fn both_splits_evenly_and_clamps_when_image_small() {
        let cfg = PartialScanConfig {
            max_bytes: 1_000,
            scan_region: ScanRegion::Both,
            plugins: Vec::new(),
        };
        let regions = cfg.regions(10_000);
        assert_eq!(regions, vec![(0, 500), (9_500, 500)]);
        // Small image where the two halves overlap → fall back to full.
        let regions = cfg.regions(600);
        assert_eq!(regions, vec![(0, 600)]);
    }

    #[test]
    fn caveat_only_present_in_partial_mode() {
        let cfg = PartialScanConfig::default();
        assert!(cfg.caveat(1_000_000).is_none());
        let partial = PartialScanConfig {
            max_bytes: 100,
            scan_region: ScanRegion::FromStart,
            plugins: Vec::new(),
        };
        assert!(partial.caveat(1_000).unwrap().contains("PARTIAL SCAN"));
    }

    #[test]
    fn plugin_partial_scan_support_list() {
        assert!(supports_partial_scan("phantom"));
        assert!(supports_partial_scan("Strata Carbon"));
        assert!(!supports_partial_scan("recon"));
    }
}

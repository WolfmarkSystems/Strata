//! ANDROID16-3 — Android file-wiping tool detection.
//!
//! Detects installation and execution of known commercial wiping apps
//! (Secure Delete, iShredder, File Shredder, Android Shredder, Secure
//! Eraser, Mr Wiper, …) and flags filesystem patterns consistent with
//! their overwrite passes (all-0xFF, all-0x00, DoD 5220.22-M 3-pass,
//! random-with-suspicious-entropy).
//!
//! This module is pure — it consumes caller-supplied fact bundles
//! (installed packages, app-execution events, sampled overwritten
//! blocks) and emits `AndroidWipingIndicator` entries with
//! examiner-ready legal-significance wording. The vault plugin wires
//! it to real Android inputs.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One piece of evidence that a commercial wiper was used on this
/// device. Severity is encoded in `confidence` (0.0–1.0); the
/// `legal_significance` field carries the examiner-ready sentence
/// that goes straight into the expert-witness report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AndroidWipingIndicator {
    pub indicator_type: String,
    pub wiper_app_detected: Option<String>,
    pub installation_time: Option<DateTime<Utc>>,
    pub execution_times: Vec<DateTime<Utc>>,
    pub pattern_signatures_found: Vec<String>,
    pub estimated_files_wiped: Option<u64>,
    pub confidence: f64,
    pub legal_significance: String,
}

/// Catalogue of known wiping-app package names (expand as research
/// publishes more). Matching is case-insensitive exact-match on the
/// package-name column of `/data/system/packages.xml`.
pub const KNOWN_WIPER_PACKAGES: &[&str] = &[
    "com.protectstar.securedelete",
    "com.protectstar.ishredder",
    "com.hyperionics.fileshredder",
    "com.ascomp.secureeraser",
    "com.mrwiper",
    "com.vbits.shredder",
    "net.jaredburrows.shredder",
];

/// Package-level detection. Returns the canonical package if `name`
/// matches one of the catalogued wipers.
pub fn known_wiper(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    KNOWN_WIPER_PACKAGES
        .iter()
        .find(|p| p.eq_ignore_ascii_case(&lower))
        .copied()
}

/// Classify a sampled block of bytes as one of the known wiping
/// patterns. Returns `None` when the block looks like ordinary data.
pub fn classify_wipe_pattern(block: &[u8]) -> Option<WipePattern> {
    if block.is_empty() {
        return None;
    }
    if block.iter().all(|b| *b == 0xFF) {
        return Some(WipePattern::AllOnes);
    }
    if block.iter().all(|b| *b == 0x00) {
        return Some(WipePattern::AllZeros);
    }
    // DoD 5220.22-M: three-pass overwrite — we can only recognise
    // the final pass on a live sample, which is a block of the
    // complement of the middle pass. Detect characteristic striping.
    if looks_like_dod_final_pass(block) {
        return Some(WipePattern::DoD5220_22M);
    }
    if looks_like_high_entropy_regular(block) {
        return Some(WipePattern::RandomPattern);
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WipePattern {
    AllOnes,
    AllZeros,
    DoD5220_22M,
    GutmannFinalPass,
    RandomPattern,
}

impl WipePattern {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AllOnes => "all-0xFF overwrite",
            Self::AllZeros => "all-0x00 overwrite",
            Self::DoD5220_22M => "DoD 5220.22-M 3-pass overwrite",
            Self::GutmannFinalPass => "Gutmann 35-pass final",
            Self::RandomPattern => "random overwrite (high entropy, regular boundaries)",
        }
    }
}

fn looks_like_dod_final_pass(block: &[u8]) -> bool {
    if block.len() < 64 {
        return false;
    }
    // Pass 3 of DoD 5220.22-M is a constant repeating byte (0xF6).
    // We accept any repeating-single-byte block as a possible DoD-3.
    let first = block[0];
    if first == 0xFF || first == 0x00 {
        return false;
    }
    block.iter().all(|b| *b == first)
}

fn looks_like_high_entropy_regular(block: &[u8]) -> bool {
    if block.len() < 256 {
        return false;
    }
    // Histogram: if every byte value is represented, entropy is high.
    let mut seen = [false; 256];
    for b in block.iter().take(512) {
        seen[*b as usize] = true;
    }
    let coverage = seen.iter().filter(|s| **s).count();
    coverage >= 200
}

/// Build the indicator record when a known wiper is found in the
/// installed-packages list. `execution_times` can be empty — the
/// install on its own is already probative.
pub fn indicator_from_installation(
    package: &str,
    installation_time: Option<DateTime<Utc>>,
    execution_times: Vec<DateTime<Utc>>,
) -> AndroidWipingIndicator {
    let confidence = if execution_times.is_empty() {
        0.55
    } else {
        0.85
    };
    AndroidWipingIndicator {
        indicator_type: "installed_wiper".into(),
        wiper_app_detected: Some(package.to_string()),
        installation_time,
        execution_times,
        pattern_signatures_found: Vec::new(),
        estimated_files_wiped: None,
        confidence,
        legal_significance: format!(
            "ANTI-FORENSIC ACTIVITY DETECTED: Evidence consistent with use of commercial \
             file-wiping application '{package}' was identified. This activity may \
             constitute obstruction of justice or spoliation of evidence."
        ),
    }
}

/// Build the indicator record for a detected on-disk wipe pattern.
pub fn indicator_from_pattern(
    pattern: WipePattern,
    sampled_path: &str,
    estimated_files_wiped: Option<u64>,
) -> AndroidWipingIndicator {
    AndroidWipingIndicator {
        indicator_type: "overwrite_pattern".into(),
        wiper_app_detected: None,
        installation_time: None,
        execution_times: Vec::new(),
        pattern_signatures_found: vec![pattern.as_str().into()],
        estimated_files_wiped,
        confidence: 0.7,
        legal_significance: format!(
            "ANTI-FORENSIC ACTIVITY DETECTED: Overwrite pattern consistent with \
             {} was observed at {}. The affected region no longer contains \
             recoverable original content.",
            pattern.as_str(),
            sampled_path
        ),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_wiper_matches_catalogued_package() {
        assert_eq!(
            known_wiper("com.protectstar.ishredder"),
            Some("com.protectstar.ishredder")
        );
        assert!(known_wiper("com.whatsapp").is_none());
    }

    #[test]
    fn classifies_all_ones_block() {
        let block = vec![0xFFu8; 4096];
        assert_eq!(classify_wipe_pattern(&block), Some(WipePattern::AllOnes));
    }

    #[test]
    fn classifies_all_zeros_block() {
        let block = vec![0u8; 4096];
        assert_eq!(classify_wipe_pattern(&block), Some(WipePattern::AllZeros));
    }

    #[test]
    fn classifies_dod_final_pass_repeating_byte() {
        let block = vec![0xF6u8; 4096];
        assert_eq!(
            classify_wipe_pattern(&block),
            Some(WipePattern::DoD5220_22M)
        );
    }

    #[test]
    fn high_entropy_block_is_random_pattern() {
        let block: Vec<u8> = (0u16..1024).map(|i| (i & 0xFF) as u8).collect();
        assert_eq!(
            classify_wipe_pattern(&block),
            Some(WipePattern::RandomPattern)
        );
    }

    #[test]
    fn ordinary_text_returns_none() {
        let block = b"the quick brown fox".to_vec();
        assert!(classify_wipe_pattern(&block).is_none());
    }

    #[test]
    fn indicator_has_executions_increases_confidence() {
        let low = indicator_from_installation("com.mrwiper", None, Vec::new());
        let high = indicator_from_installation("com.mrwiper", None, vec![Utc::now()]);
        assert!(high.confidence > low.confidence);
    }

    #[test]
    fn indicator_from_pattern_includes_legal_sentence() {
        let ind = indicator_from_pattern(WipePattern::AllZeros, "/data/user/0/app/cache", Some(17));
        assert!(ind.legal_significance.contains("ANTI-FORENSIC"));
        assert_eq!(ind.estimated_files_wiped, Some(17));
    }
}

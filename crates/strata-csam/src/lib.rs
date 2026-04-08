//! # CSAM Detection Module
//!
//! ## Legal Notice
//!
//! This module provides hash-based detection of known CSAM
//! (Child Sexual Abuse Material) for use by law enforcement
//! and certified forensic examiners only.
//!
//! ## Hash Set Licensing
//!
//! This module does NOT include or bundle any CSAM hash data.
//! Examiners must import their own vetted hash sets obtained
//! through authorized channels:
//!
//! - NCMEC (National Center for Missing & Exploited Children)
//!   https://www.missingkids.org/
//!
//! - Project VIC International
//!   https://www.projectvic.org/
//!
//! ## Mandatory Reporting
//!
//! Discovery of CSAM during a forensic examination creates
//! mandatory reporting obligations under 18 U.S.C. § 2258A
//! and applicable state laws. Examiners are responsible for
//! compliance with all applicable reporting requirements.
//!
//! ## Examiner Responsibility
//!
//! All findings must be reviewed by a qualified examiner.
//! This tool produces intelligence, not conclusions.
//! The examiner bears professional and legal responsibility
//! for all findings submitted in legal proceedings.

pub mod audit;
pub mod hash_db;
pub mod perceptual;
pub mod report;
pub mod scanner;

pub use audit::{CsamAuditAction, CsamAuditEntry, CsamAuditLog};
pub use hash_db::{CsamHashDb, HashSetFormat};
pub use perceptual::PerceptualHashDb;
pub use report::{CsamReport, HashSetSummary, ScanConfigSummary};
pub use scanner::{CsamScanner, ScanConfig, ScanProgress};

/// Result of a CSAM scan on a single file.
///
/// Every hit produced by the scanner is examiner-reviewable and
/// recorded into the immutable audit log. Hits are never
/// auto-confirmed — `examiner_reviewed` and `examiner_confirmed`
/// must be set explicitly by examiner action.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CsamHit {
    pub hit_id: uuid::Uuid,
    pub file_path: String,
    pub file_size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub match_type: MatchType,
    /// Name of the hash set that produced the match.
    pub match_source: String,
    pub perceptual_hash: Option<String>,
    /// Hamming distance to the matched perceptual hash.
    /// 0 = identical, <10 = likely match.
    pub perceptual_distance: Option<u32>,
    pub confidence: Confidence,
    pub timestamp_utc: chrono::DateTime<chrono::Utc>,
    pub examiner_reviewed: bool,
    pub examiner_confirmed: bool,
    pub examiner_notes: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MatchType {
    ExactMd5,
    ExactSha1,
    ExactSha256,
    /// PhotoDNA-style perceptual match (dHash).
    Perceptual,
}

impl MatchType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MatchType::ExactMd5 => "ExactMd5",
            MatchType::ExactSha1 => "ExactSha1",
            MatchType::ExactSha256 => "ExactSha256",
            MatchType::Perceptual => "Perceptual",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Confidence {
    /// Exact cryptographic hash match.
    Confirmed,
    /// Perceptual distance 0-5.
    High,
    /// Perceptual distance 6-10.
    Medium,
    /// Perceptual distance 11-15.
    NeedsReview,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Confirmed => "Confirmed",
            Confidence::High => "High",
            Confidence::Medium => "Medium",
            Confidence::NeedsReview => "NeedsReview",
        }
    }

    /// Map a perceptual Hamming distance to a confidence bucket.
    /// Distances above 15 are not considered hits at all.
    pub fn from_perceptual_distance(distance: u32) -> Option<Self> {
        match distance {
            0..=5 => Some(Confidence::High),
            6..=10 => Some(Confidence::Medium),
            11..=15 => Some(Confidence::NeedsReview),
            _ => None,
        }
    }
}

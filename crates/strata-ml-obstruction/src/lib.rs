//! Anti-forensic behavior scoring for Strata.
//!
//! Produces a single Obstruction Score (0–100) that summarizes all detected
//! anti-forensic behavior into one number that prosecutors and judges can
//! understand. The score is **always advisory** and clearly labeled.
//!
//! Available on **all license tiers**.

pub mod detector;
pub mod scorer;

pub use detector::{AntiForensicDetector, DetectedBehavior};
pub use scorer::{ObstructionAssessment, ObstructionScorer, ObstructionSeverity, ScoringFactor};

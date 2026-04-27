//! # strata-ml-charges — Charge-to-Evidence Mapping
//!
//! Rule-based charge suggestion and evidence gap analysis for Strata.
//! Maps artifacts found to selected charges, suggests additional charges
//! based on artifact patterns, and identifies evidence gaps for follow-up.
//!
//! All output is **ADVISORY ONLY**. Charging decisions require review
//! by legal counsel. This system provides investigative guidance, not
//! legal conclusions.
//!
//! Gov/Mil only — requires strata-charges feature.

pub mod engine;
pub mod gap_analyzer;
pub mod matrix;
pub mod rules;
pub mod types;

pub use engine::analyze;
pub use types::*;

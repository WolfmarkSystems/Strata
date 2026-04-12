//! # strata-ml-anomaly — Statistical Anomaly Detection
//!
//! On-device statistical anomaly detection for artifact timelines.
//! Runs after all plugins complete and flags artifacts that are
//! unusual relative to the device's own behavioral baseline.
//!
//! All findings are **ML-ASSISTED** and **ADVISORY ONLY**. They
//! require examiner review and independent corroboration before
//! inclusion in forensic reports. Anomaly detection does not
//! constitute a forensic finding.
//!
//! Runs completely offline. No API calls, no cloud, ever.

pub mod types;
pub mod features;
pub mod detectors;
pub mod engine;

pub use engine::{AnomalyConfig, AnomalyEngine, DetectorSet, ADVISORY_NOTICE};
pub use types::*;

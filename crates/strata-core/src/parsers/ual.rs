//! User Access Logging (UAL) parser.
//!
//! Windows Server only. UAL records every authenticated client connection
//! to the server, including username, source IP, auth type, and first/last
//! access timestamps. Retains ~2 years of history. The single richest
//! artifact for lateral movement investigations on servers.
//!
//! Storage format: ESE (Extensible Storage Engine) databases at
//! `C:\Windows\System32\LogFiles\Sum\*.mdb` and `Current.mdb`.
//!
//! Status: scaffolding. Full implementation requires an ESE reader
//! (libesedb equivalent). For v1.0.0 we surface the presence of the
//! database files as high-value evidence and direct examiners to offline
//! analysis tools (KStrike, SumECmd).

use crate::errors::ForensicError;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct UalEntry {
    pub username: String,
    pub source_ip: String,
    pub auth_type: String,
    pub first_access: String,
    pub last_access: String,
    pub role: String,
}

pub struct UalParser;

impl UalParser {
    /// Detect UAL evidence in the given directory. Returns the list of
    /// `.mdb` files found in `LogFiles\Sum\`, which is sufficient evidence
    /// to surface to the UI / examiner.
    pub fn detect_sum_dir(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("mdb") {
                out.push(p);
            }
        }
        out
    }

    /// Parse a UAL `.mdb` file into a Vec of client connection records.
    ///
    /// Stub — returns an empty list. Real implementation requires an ESE
    /// reader. Day 11+ follow-up.
    pub fn parse_mdb(_path: &Path) -> Result<Vec<UalEntry>, ForensicError> {
        Ok(vec![])
    }
}

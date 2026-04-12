//! Chain of custody logging — tamper-evident record of every significant
//! action taken during a forensic examination.
//!
//! Each entry is SHA256-chained to the previous entry, forming an
//! append-only log where any modification or deletion is detectable.
//! The chain can be exported as a PDF/text chain of custody report for
//! court submissions.
//!
//! Actions logged automatically:
//! - Evidence loaded (hash verified)
//! - Plugin analysis started/completed
//! - Artifact viewed / exported
//! - Report generated
//! - CSAM review actions
//! - Court mode toggled
//! - Examiner notes added/edited

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub id: String,
    pub sequence: u64,
    pub timestamp: String,
    pub action: String,
    pub examiner: String,
    pub details: String,
    pub evidence_hash: Option<String>,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CustodyError {
    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("Chain integrity failure at sequence {0}")]
    ChainBroken(u64),
}

/// SHA256-chained custody log stored in SQLite.
pub struct CustodyLog {
    conn: Connection,
}

impl CustodyLog {
    /// Open or create the custody table in an existing case database.
    pub fn open(conn: Connection) -> Result<Self, CustodyError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS custody_log (
                id TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                examiner TEXT NOT NULL,
                details TEXT NOT NULL,
                evidence_hash TEXT,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );",
        )?;
        Ok(Self { conn })
    }

    /// Open an in-memory log (for testing).
    pub fn open_memory() -> Result<Self, CustodyError> {
        let conn = Connection::open_in_memory()?;
        Self::open(conn)
    }

    /// Record a new custody event. The entry is SHA256-chained to the
    /// previous entry automatically.
    pub fn record(
        &self,
        action: &str,
        examiner: &str,
        details: &str,
        evidence_hash: Option<&str>,
    ) -> Result<CustodyEntry, CustodyError> {
        let sequence = self.next_sequence()?;
        let timestamp =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let prev_hash = self.last_hash()?;
        let entry_hash = compute_entry_hash(
            sequence,
            &timestamp,
            action,
            examiner,
            details,
            evidence_hash,
            &prev_hash,
        );
        let id = uuid::Uuid::new_v4().to_string();

        self.conn.execute(
            "INSERT INTO custody_log (id, sequence, timestamp, action, examiner, details, evidence_hash, prev_hash, entry_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id,
                sequence,
                timestamp,
                action,
                examiner,
                details,
                evidence_hash,
                prev_hash,
                entry_hash,
            ],
        )?;

        Ok(CustodyEntry {
            id,
            sequence,
            timestamp,
            action: action.to_string(),
            examiner: examiner.to_string(),
            details: details.to_string(),
            evidence_hash: evidence_hash.map(String::from),
            prev_hash,
            entry_hash,
        })
    }

    /// Verify the entire chain. Returns the number of entries if valid.
    pub fn verify_chain(&self) -> Result<usize, CustodyError> {
        let entries = self.all_entries()?;
        let mut expected_prev = "0".repeat(64);
        for entry in &entries {
            if entry.prev_hash != expected_prev {
                return Err(CustodyError::ChainBroken(entry.sequence));
            }
            let computed = compute_entry_hash(
                entry.sequence,
                &entry.timestamp,
                &entry.action,
                &entry.examiner,
                &entry.details,
                entry.evidence_hash.as_deref(),
                &entry.prev_hash,
            );
            if computed != entry.entry_hash {
                return Err(CustodyError::ChainBroken(entry.sequence));
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(entries.len())
    }

    /// Get all entries in sequence order.
    pub fn all_entries(&self) -> Result<Vec<CustodyEntry>, CustodyError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sequence, timestamp, action, examiner, details, \
             evidence_hash, prev_hash, entry_hash \
             FROM custody_log ORDER BY sequence",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(CustodyEntry {
                id: row.get(0)?,
                sequence: row.get(1)?,
                timestamp: row.get(2)?,
                action: row.get(3)?,
                examiner: row.get(4)?,
                details: row.get(5)?,
                evidence_hash: row.get(6)?,
                prev_hash: row.get(7)?,
                entry_hash: row.get(8)?,
            })
        })?;
        Ok(rows.flatten().collect())
    }

    /// Count entries.
    pub fn count(&self) -> Result<usize, CustodyError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM custody_log", [], |row| row.get(0))?;
        Ok(n as usize)
    }

    /// Format the custody log as a text report suitable for PDF export.
    pub fn format_report(&self, case_name: &str, examiner: &str) -> Result<String, CustodyError> {
        let entries = self.all_entries()?;
        let chain_status = match self.verify_chain() {
            Ok(n) => format!("VERIFIED — {} entries, chain intact", n),
            Err(CustodyError::ChainBroken(seq)) => {
                format!("BROKEN — chain integrity failure at sequence {}", seq)
            }
            Err(e) => format!("ERROR — {}", e),
        };

        let mut out = String::new();
        out.push_str("═══════════════════════════════════════════════════════════════\n");
        out.push_str("CHAIN OF CUSTODY REPORT\n");
        out.push_str("═══════════════════════════════════════════════════════════════\n\n");
        out.push_str(&format!("Case: {}\n", case_name));
        out.push_str(&format!("Examiner: {}\n", examiner));
        out.push_str(&format!(
            "Report generated: {}\n",
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ));
        out.push_str(&format!("Chain status: {}\n", chain_status));
        out.push_str(&format!("Total events: {}\n\n", entries.len()));

        out.push_str("─────────────────────────────────────────────────────────────\n");
        out.push_str("SEQ  TIMESTAMP                 ACTION                EXAMINER\n");
        out.push_str("─────────────────────────────────────────────────────────────\n");

        for entry in &entries {
            out.push_str(&format!(
                "{:<4} {:<25} {:<21} {}\n",
                entry.sequence, entry.timestamp, entry.action, entry.examiner,
            ));
            if !entry.details.is_empty() {
                out.push_str(&format!("     {}\n", entry.details));
            }
            if let Some(ref eh) = entry.evidence_hash {
                out.push_str(&format!("     Evidence SHA-256: {}\n", eh));
            }
        }

        out.push_str("\n─────────────────────────────────────────────────────────────\n");
        out.push_str(&format!("Chain verification: {}\n", chain_status));
        out.push_str("═══════════════════════════════════════════════════════════════\n");

        Ok(out)
    }

    fn next_sequence(&self) -> Result<u64, CustodyError> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(sequence), -1) FROM custody_log",
                [],
                |row| row.get(0),
            )?;
        Ok((n + 1) as u64)
    }

    fn last_hash(&self) -> Result<String, CustodyError> {
        let hash: Option<String> = self
            .conn
            .query_row(
                "SELECT entry_hash FROM custody_log ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();
        Ok(hash.unwrap_or_else(|| "0".repeat(64)))
    }
}

fn compute_entry_hash(
    sequence: u64,
    timestamp: &str,
    action: &str,
    examiner: &str,
    details: &str,
    evidence_hash: Option<&str>,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sequence.to_le_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(action.as_bytes());
    hasher.update(examiner.as_bytes());
    hasher.update(details.as_bytes());
    if let Some(eh) = evidence_hash {
        hasher.update(eh.as_bytes());
    }
    hasher.update(prev_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Standard action constants for consistency across the codebase.
pub mod actions {
    pub const EVIDENCE_LOADED: &str = "EVIDENCE_LOADED";
    pub const EVIDENCE_HASH_VERIFIED: &str = "EVIDENCE_HASH_VERIFIED";
    pub const PLUGIN_STARTED: &str = "PLUGIN_STARTED";
    pub const PLUGIN_COMPLETED: &str = "PLUGIN_COMPLETED";
    pub const ARTIFACT_VIEWED: &str = "ARTIFACT_VIEWED";
    pub const ARTIFACT_EXPORTED: &str = "ARTIFACT_EXPORTED";
    pub const REPORT_GENERATED: &str = "REPORT_GENERATED";
    pub const CSAM_SCAN_STARTED: &str = "CSAM_SCAN_STARTED";
    pub const CSAM_SCAN_COMPLETED: &str = "CSAM_SCAN_COMPLETED";
    pub const CSAM_HIT_CONFIRMED: &str = "CSAM_HIT_CONFIRMED";
    pub const CSAM_HIT_DISMISSED: &str = "CSAM_HIT_DISMISSED";
    pub const CSAM_IMAGE_REVIEWED: &str = "CSAM_IMAGE_REVIEWED";
    pub const COURT_MODE_ENABLED: &str = "COURT_MODE_ENABLED";
    pub const COURT_MODE_DISABLED: &str = "COURT_MODE_DISABLED";
    pub const NOTE_ADDED: &str = "NOTE_ADDED";
    pub const NOTE_EDITED: &str = "NOTE_EDITED";
    pub const CASE_OPENED: &str = "CASE_OPENED";
    pub const CASE_SAVED: &str = "CASE_SAVED";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_retrieve_entries() {
        let log = CustodyLog::open_memory().unwrap();
        log.record(
            actions::EVIDENCE_LOADED,
            "SA Randolph",
            "Loaded evidence: suspect_drive.E01",
            Some("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
        )
        .unwrap();
        log.record(
            actions::PLUGIN_STARTED,
            "SA Randolph",
            "Started plugin: Strata Trace",
            None,
        )
        .unwrap();

        assert_eq!(log.count().unwrap(), 2);
        let entries = log.all_entries().unwrap();
        assert_eq!(entries[0].sequence, 0);
        assert_eq!(entries[1].sequence, 1);
        assert_eq!(entries[0].action, "EVIDENCE_LOADED");
        assert!(entries[0].evidence_hash.is_some());
    }

    #[test]
    fn chain_verifies_when_intact() {
        let log = CustodyLog::open_memory().unwrap();
        log.record(actions::CASE_OPENED, "SA Smith", "New case", None)
            .unwrap();
        log.record(actions::EVIDENCE_LOADED, "SA Smith", "drive.E01", None)
            .unwrap();
        log.record(actions::PLUGIN_STARTED, "SA Smith", "Trace", None)
            .unwrap();

        let count = log.verify_chain().unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn chain_detects_tampering() {
        let log = CustodyLog::open_memory().unwrap();
        log.record(actions::CASE_OPENED, "SA Smith", "New case", None)
            .unwrap();
        log.record(actions::EVIDENCE_LOADED, "SA Smith", "drive.E01", None)
            .unwrap();

        // Tamper with the first entry's hash
        log.conn
            .execute(
                "UPDATE custody_log SET entry_hash = 'tampered' WHERE sequence = 0",
                [],
            )
            .unwrap();

        let result = log.verify_chain();
        assert!(result.is_err());
        match result {
            Err(CustodyError::ChainBroken(seq)) => assert_eq!(seq, 0),
            _ => panic!("expected ChainBroken"),
        }
    }

    #[test]
    fn entries_are_sha256_chained() {
        let log = CustodyLog::open_memory().unwrap();
        let e1 = log
            .record(actions::CASE_OPENED, "SA A", "first", None)
            .unwrap();
        let e2 = log
            .record(actions::EVIDENCE_LOADED, "SA A", "second", None)
            .unwrap();

        // e2.prev_hash must equal e1.entry_hash
        assert_eq!(e2.prev_hash, e1.entry_hash);
        // First entry's prev_hash is the zero hash
        assert_eq!(e1.prev_hash, "0".repeat(64));
    }

    #[test]
    fn format_report_includes_all_entries() {
        let log = CustodyLog::open_memory().unwrap();
        log.record(actions::CASE_OPENED, "SA Randolph", "CID-2026", None)
            .unwrap();
        log.record(
            actions::EVIDENCE_LOADED,
            "SA Randolph",
            "suspect.E01",
            Some("abcd1234"),
        )
        .unwrap();

        let report = log.format_report("CID-2026", "SA Randolph").unwrap();
        assert!(report.contains("CHAIN OF CUSTODY REPORT"));
        assert!(report.contains("CID-2026"));
        assert!(report.contains("EVIDENCE_LOADED"));
        assert!(report.contains("Evidence SHA-256: abcd1234"));
        assert!(report.contains("VERIFIED"));
    }

    #[test]
    fn empty_log_verifies_successfully() {
        let log = CustodyLog::open_memory().unwrap();
        let count = log.verify_chain().unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn serializes_to_json() {
        let log = CustodyLog::open_memory().unwrap();
        let entry = log
            .record(actions::CASE_OPENED, "SA Test", "test", None)
            .unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        let rt: CustodyEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.action, "CASE_OPENED");
        assert_eq!(rt.sequence, 0);
    }
}

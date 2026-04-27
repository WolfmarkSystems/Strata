//! NSRL + threat-intel pre-filter pass.
//!
//! After the master index is built, walks every indexed SHA-256 and
//! tags rows against loaded NSRL and threat-intel feeds. Output is
//! purely in-index flag updates — no separate report stream.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use crate::hashset::nsrl::NsrlDatabase;
use crate::intel::local_feed::ThreatIntelDatabase;

use super::database::{FileIndex, FileIndexError};

#[derive(Debug, Clone, Default)]
pub struct PrefilterReport {
    pub nsrl_matches: u64,
    pub threat_intel_matches: u64,
}

/// Run pre-filter over every indexed row that has a sha256. Accepts
/// optional NSRL and threat-intel databases; either side may be
/// omitted when unavailable.
pub fn run_prefilter(
    index: &mut FileIndex,
    nsrl: Option<&NsrlDatabase>,
    intel: Option<&ThreatIntelDatabase>,
) -> Result<PrefilterReport, FileIndexError> {
    let mut report = PrefilterReport::default();
    let entries = enumerate_entries(index)?;
    for (sha256_hex, sha256_bytes) in entries {
        if let Some(nsrl) = nsrl {
            if let Some(array) = sha256_bytes.as_deref().and_then(try_into_32) {
                if nsrl.is_known_good_sha256(&array) {
                    index.mark_nsrl(&sha256_hex)?;
                    report.nsrl_matches += 1;
                }
            }
        }
        if let Some(intel) = intel {
            if let Some(array) = sha256_bytes.as_deref().and_then(try_into_32) {
                if let Some(name) = intel.hash_known_bad_sha256(&array) {
                    index.mark_threat_intel(&sha256_hex, &name)?;
                    report.threat_intel_matches += 1;
                }
            }
        }
    }
    Ok(report)
}

type Sha256HexAndBytes = (String, Option<Vec<u8>>);

fn enumerate_entries(index: &FileIndex) -> Result<Vec<Sha256HexAndBytes>, FileIndexError> {
    let mut stmt = index
        .connection_ref()
        .prepare("SELECT sha256 FROM file_index WHERE sha256 IS NOT NULL")?;
    let rows = stmt.query_map([], |row| {
        let hex: String = row.get(0)?;
        Ok(hex)
    })?;
    let mut out = Vec::new();
    for row in rows {
        let hex = row?;
        let bytes = hex_decode(&hex);
        out.push((hex, bytes));
    }
    Ok(out)
}

fn try_into_32(v: &[u8]) -> Option<[u8; 32]> {
    if v.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(v);
    Some(arr)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_index::database::FileIndexEntry;

    fn open_idx() -> (tempfile::TempDir, FileIndex) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("idx.db");
        (dir, FileIndex::open(&path).expect("open"))
    }

    fn entry_with_hash(hex: &str) -> FileIndexEntry {
        let mut e = FileIndexEntry::new("/e/a".into(), "a".into(), 1);
        e.sha256 = Some(hex.into());
        e
    }

    #[test]
    fn run_prefilter_noop_without_feeds() {
        let (_dir, mut idx) = open_idx();
        idx.upsert_batch(&[entry_with_hash("aa".repeat(32).as_str())])
            .expect("ins");
        let report = run_prefilter(&mut idx, None, None).expect("run");
        assert_eq!(report.nsrl_matches, 0);
        assert_eq!(report.threat_intel_matches, 0);
    }

    #[test]
    fn hex_decode_handles_valid_input() {
        assert_eq!(hex_decode("aabbccdd"), Some(vec![0xAA, 0xBB, 0xCC, 0xDD]));
        assert!(hex_decode("abc").is_none());
    }

    #[test]
    fn try_into_32_rejects_wrong_length() {
        assert!(try_into_32(&[0u8; 31]).is_none());
        assert!(try_into_32(&[0u8; 32]).is_some());
    }
}

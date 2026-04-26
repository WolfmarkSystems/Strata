use once_cell::sync::Lazy;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CustodyEntry {
    pub timestamp: i64,
    pub examiner: String,
    pub action: String,
    pub evidence_id: String,
    pub details: String,
    pub hash_before: Option<String>,
    pub hash_after: Option<String>,
}

static CUSTODY_LOG: Lazy<Mutex<Vec<CustodyEntry>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn log_custody(entry: CustodyEntry) {
    if let Ok(mut log) = CUSTODY_LOG.lock() {
        log.push(entry);
    }
}

pub fn get_custody_log(evidence_id: &str) -> Vec<CustodyEntry> {
    CUSTODY_LOG
        .lock()
        .map(|log| {
            log.iter()
                .filter(|entry| entry.evidence_id == evidence_id)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn sha256_file(path: &Path) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

#[cfg(test)]
pub fn clear_custody_log() {
    if let Ok(mut log) = CUSTODY_LOG.lock() {
        log.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_log_records_evidence_load() {
        clear_custody_log();
        log_custody(CustodyEntry {
            timestamp: 1,
            examiner: "Examiner".to_string(),
            action: "evidence_loaded".to_string(),
            evidence_id: "ev1".to_string(),
            details: "Loaded /tmp/evidence".to_string(),
            hash_before: Some("abc".to_string()),
            hash_after: Some("abc".to_string()),
        });

        let log = get_custody_log("ev1");
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action, "evidence_loaded");
        assert_eq!(log[0].hash_before.as_deref(), Some("abc"));
    }

    #[test]
    fn custody_log_is_append_only() {
        clear_custody_log();
        for idx in 0..3 {
            log_custody(CustodyEntry {
                timestamp: idx,
                examiner: "Examiner".to_string(),
                action: format!("action_{idx}"),
                evidence_id: "ev2".to_string(),
                details: idx.to_string(),
                hash_before: None,
                hash_after: None,
            });
        }

        let log = get_custody_log("ev2");
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].action, "action_0");
        assert_eq!(log[2].action, "action_2");
    }
}

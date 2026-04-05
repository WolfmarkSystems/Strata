use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::event::{AuditEvent, AuditEventType};

#[derive(Clone)]
pub struct AuditLogger {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Append an audited event with hash chaining.
    ///
    /// event_hash = SHA256( prev_hash || "|" || sequence || "|" || event_id || "|" || case_id || "|" || timestamp || "|" || event_json )
    pub fn log(&self, case_id: Uuid, event: AuditEventType) {
        let mut events = match self.events.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let sequence = events.len() as u64;
        let prev_hash = events.last().map(|e| e.event_hash.clone());

        let event_id = Uuid::new_v4();
        let timestamp_utc = OffsetDateTime::now_utc();

        let event_hash = compute_event_hash(
            prev_hash.as_deref(),
            sequence,
            event_id,
            case_id,
            timestamp_utc,
            &event,
        );

        events.push(AuditEvent {
            sequence,
            event_id,
            case_id,
            timestamp_utc,
            prev_hash,
            event_hash,
            event,
        });
    }

    pub fn all_events(&self) -> Vec<AuditEvent> {
        match self.events.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Convenience getter for the current chain tip.
    pub fn last_hash_hex(&self) -> String {
        match self.events.lock() {
            Ok(g) => g
                .last()
                .map(|e| e.event_hash.clone())
                .unwrap_or_else(|| "NO_EVENTS".to_string()),
            Err(poisoned) => poisoned
                .into_inner()
                .last()
                .map(|e| e.event_hash.clone())
                .unwrap_or_else(|| "NO_EVENTS".to_string()),
        }
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_event_hash(
    prev_hash: Option<&str>,
    sequence: u64,
    event_id: Uuid,
    case_id: Uuid,
    timestamp_utc: OffsetDateTime,
    event: &AuditEventType,
) -> String {
    let ts = timestamp_utc
        .format(&Rfc3339)
        .unwrap_or_else(|_| "INVALID_TIMESTAMP".to_string());

    // Deterministic enough for this project:
    // - struct field order is stable in serde_json for Rust structs
    // - enums serialize deterministically by variant + fields
    let event_json = serde_json::to_string(event).unwrap_or_else(|_| "\"SERDE_ERROR\"".to_string());

    let prev = prev_hash.unwrap_or("GENESIS");

    let material = format!("{prev}|{sequence}|{event_id}|{case_id}|{ts}|{event_json}");

    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    format!("{:x}", hasher.finalize())
}

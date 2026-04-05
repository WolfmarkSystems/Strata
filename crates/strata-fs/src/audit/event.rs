use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AuditEventType {
    // ---- Case lifecycle ----
    CaseStarted {
        tool_name: String,
        tool_version: String,
        evidence_path: String,
        evidence_size: u64,
        scan_mode: String,
    },
    CaseClosed {
        final_audit_hash: String,
    },

    // ---- Evidence actions ----
    EvidenceOpened,
    EvidenceRead {
        offset: u64,
        length: u64,
    },

    // ---- Policy enforcement ----
    PolicyModeChanged {
        from: String,
        to: String,
    },
    AllowedRangeAdded {
        offset: u64,
        length: u64,
        label: String,
    },
    ReadBlocked {
        offset: u64,
        length: u64,
        reason: String,
    },

    // ---- Detection events ----
    DiskLayoutDetected {
        layout: String,
    },
    FileSystemDetected {
        filesystem: String,
    },
    FileSystemMetadata {
        filesystem: String,
        label: String,
        serial: Option<u32>,
        cluster_size: u64,
        total_clusters: u32,
        free_clusters: Option<u32>,
    },

    // NEW: volume enumeration (Phase 2)
    VolumeDetected {
        index: u32,
        base_offset: u64,
        size: u64,
        kind: String,
    },

    // ---- Hashing ----
    HashComputed {
        md5: Option<String>,
        sha1: Option<String>,
        sha256: Option<String>,
    },

    // ---- Carving ----
    CarveStarted {
        min_size: u64,
        max_size: u64,
    },
    CarveComplete {
        files_found: u32,
    },

    // ---- Severity ----
    Warning {
        message: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEvent {
    pub sequence: u64,
    pub event_id: Uuid,
    pub case_id: Uuid,

    #[serde(with = "time::serde::rfc3339")]
    pub timestamp_utc: OffsetDateTime,

    pub prev_hash: Option<String>,
    pub event_hash: String,
    pub event: AuditEventType,
}

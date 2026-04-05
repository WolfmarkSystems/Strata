use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: &str = "1.0";
pub const DEFAULT_CHECKPOINT_INTERVAL: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEventPayload {
    pub event_id: String,
    pub case_id: String,
    pub schema_version: String,
    pub tool_version: Option<String>,
    pub tool_build: Option<String>,
    pub evidence_id: Option<String>,
    pub volume_id: Option<String>,
    pub user_name: String,
    pub session_id: String,
    pub event_type: String,
    pub summary: String,
    pub details_json: Option<String>,
    pub ts_utc: i64,
    pub ts_local: String,
}

impl CanonicalEventPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: &str,
        case_id: &str,
        user_name: &str,
        session_id: &str,
        event_type: &str,
        summary: &str,
        ts_utc: i64,
        ts_local: &str,
    ) -> Self {
        Self {
            event_id: event_id.to_string(),
            case_id: case_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            tool_version: None,
            tool_build: None,
            evidence_id: None,
            volume_id: None,
            user_name: user_name.to_string(),
            session_id: session_id.to_string(),
            event_type: event_type.to_string(),
            summary: summary.to_string(),
            details_json: None,
            ts_utc,
            ts_local: ts_local.to_string(),
        }
    }

    pub fn with_tool_info(mut self, version: &str, build: &str) -> Self {
        self.tool_version = Some(version.to_string());
        self.tool_build = Some(build.to_string());
        self
    }

    pub fn with_evidence(mut self, evidence_id: &str, volume_id: &str) -> Self {
        self.evidence_id = Some(evidence_id.to_string());
        self.volume_id = Some(volume_id.to_string());
        self
    }

    pub fn with_details(mut self, details: &str) -> Self {
        self.details_json = Some(details.to_string());
        self
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        result.extend_from_slice(b"event_id=");
        result.extend_from_slice(self.event_id.as_bytes());
        result.push(b'\n');

        result.extend_from_slice(b"case_id=");
        result.extend_from_slice(self.case_id.as_bytes());
        result.push(b'\n');

        result.extend_from_slice(b"schema_version=");
        result.extend_from_slice(self.schema_version.as_bytes());
        result.push(b'\n');

        if let Some(ref v) = self.tool_version {
            result.extend_from_slice(b"tool_version=");
            result.extend_from_slice(v.as_bytes());
            result.push(b'\n');
        }

        if let Some(ref b) = self.tool_build {
            result.extend_from_slice(b"tool_build=");
            result.extend_from_slice(b.as_bytes());
            result.push(b'\n');
        }

        if let Some(ref e) = self.evidence_id {
            result.extend_from_slice(b"evidence_id=");
            result.extend_from_slice(e.as_bytes());
            result.push(b'\n');
        }

        if let Some(ref v) = self.volume_id {
            result.extend_from_slice(b"volume_id=");
            result.extend_from_slice(v.as_bytes());
            result.push(b'\n');
        }

        result.extend_from_slice(b"user_name=");
        result.extend_from_slice(self.user_name.as_bytes());
        result.push(b'\n');

        result.extend_from_slice(b"session_id=");
        result.extend_from_slice(self.session_id.as_bytes());
        result.push(b'\n');

        result.extend_from_slice(b"event_type=");
        result.extend_from_slice(self.event_type.as_bytes());
        result.push(b'\n');

        result.extend_from_slice(b"summary=");
        result.extend_from_slice(self.summary.as_bytes());
        result.push(b'\n');

        if let Some(ref d) = self.details_json {
            result.extend_from_slice(b"details_json=");
            result.extend_from_slice(d.as_bytes());
            result.push(b'\n');
        }

        result.extend_from_slice(b"ts_utc=");
        result.extend_from_slice(self.ts_utc.to_string().as_bytes());
        result.push(b'\n');

        result.extend_from_slice(b"ts_local=");
        result.extend_from_slice(self.ts_local.as_bytes());

        result
    }
}

pub fn compute_canonical_hash(
    payload: &CanonicalEventPayload,
    previous_hash: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();

    if let Some(prev) = previous_hash {
        hasher.update(b"prev_hash=");
        hasher.update(prev.as_bytes());
        hasher.update(b"\n");
    }

    let canonical_bytes = payload.to_canonical_bytes();
    hasher.update(&canonical_bytes);

    format!("{:x}", hasher.finalize())
}

pub fn verify_event_hash(
    payload: &CanonicalEventPayload,
    expected_hash: &str,
    previous_hash: Option<&str>,
) -> bool {
    let computed = compute_canonical_hash(payload, previous_hash);
    computed == expected_hash
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCheckpoint {
    pub id: String,
    pub case_id: String,
    pub checkpoint_id: String,
    pub checkpoint_hash: String,
    pub event_count: usize,
    pub first_event_id: String,
    pub last_event_id: String,
    pub created_at: i64,
}

pub fn create_checkpoint(
    case_id: &str,
    events: &[EventForCheckpoint],
    current_hash: &str,
) -> ChainCheckpoint {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let checkpoint_id = format!("chk_{}", now);

    ChainCheckpoint {
        id: uuid::Uuid::new_v4().to_string(),
        case_id: case_id.to_string(),
        checkpoint_id: checkpoint_id.clone(),
        checkpoint_hash: current_hash.to_string(),
        event_count: events.len(),
        first_event_id: events.first().map(|e| e.id.clone()).unwrap_or_default(),
        last_event_id: events.last().map(|e| e.id.clone()).unwrap_or_default(),
        created_at: now,
    }
}

#[derive(Debug, Clone)]
pub struct EventForCheckpoint {
    pub id: String,
    pub event_hash: String,
}

pub fn verify_chain_with_checkpoints(
    events: &[HashEventPair],
    checkpoints: &[ChainCheckpoint],
    from_checkpoint_id: Option<&str>,
) -> ChainVerificationResult {
    let mut prev_hash: Option<String> = None;
    let mut start_index = 0;

    if let Some(chk_id) = from_checkpoint_id {
        if let Some(chk) = checkpoints.iter().find(|c| c.checkpoint_id == chk_id) {
            prev_hash = Some(chk.checkpoint_hash.clone());
            start_index = events
                .iter()
                .position(|e| e.id == chk.last_event_id)
                .map(|i| i + 1)
                .unwrap_or(0);
        }
    }

    let mut verified = 0;
    let mut failed = 0;
    let mut failed_at = None;

    for (i, event) in events.iter().enumerate().skip(start_index) {
        let expected_hash = compute_canonical_hash(
            &CanonicalEventPayload::new(
                &event.id,
                &event.case_id,
                &event.user_name,
                &event.session_id,
                &event.event_type,
                &event.summary,
                event.ts_utc,
                &event.ts_local,
            )
            .with_tool_info(
                event.tool_version.as_deref().unwrap_or("unknown"),
                event.tool_build.as_deref().unwrap_or("unknown"),
            ),
            prev_hash.as_deref(),
        );

        if expected_hash == event.event_hash {
            verified += 1;
            prev_hash = Some(event.event_hash.clone());
        } else {
            failed += 1;
            failed_at = Some(i);
            break;
        }
    }

    ChainVerificationResult {
        verified_count: verified,
        failed_count: failed,
        failed_at_index: failed_at,
        is_valid: failed == 0,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashEventPair {
    pub id: String,
    pub case_id: String,
    pub user_name: String,
    pub session_id: String,
    pub event_type: String,
    pub summary: String,
    pub ts_utc: i64,
    pub ts_local: String,
    pub tool_version: Option<String>,
    pub tool_build: Option<String>,
    pub event_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationResult {
    pub verified_count: usize,
    pub failed_count: usize,
    pub failed_at_index: Option<usize>,
    pub is_valid: bool,
}

pub struct ImmutabilityRules {
    pub activity_log_immutable: bool,
    pub exhibits_immutable: bool,
    pub enforce_on_insert: bool,
    pub log_violations: bool,
}

impl Default for ImmutabilityRules {
    fn default() -> Self {
        Self {
            activity_log_immutable: true,
            exhibits_immutable: true,
            enforce_on_insert: true,
            log_violations: true,
        }
    }
}

pub fn check_immutable_violation(
    rules: &ImmutabilityRules,
    table_name: &str,
    operation: &str,
) -> Option<String> {
    match table_name {
        "activity_log" if rules.activity_log_immutable => {
            if operation == "UPDATE" || operation == "DELETE" {
                return Some(format!(
                    "{} on {} violates immutability rule",
                    operation, table_name
                ));
            }
        }
        "exhibits" if rules.exhibits_immutable => {
            if operation == "UPDATE" || operation == "DELETE" {
                return Some(format!(
                    "{} on {} violates immutability rule",
                    operation, table_name
                ));
            }
        }
        _ => {}
    }
    None
}

pub struct FtsIndexManager {
    pub batch_size: usize,
    pub max_queue_size: usize,
}

impl Default for FtsIndexManager {
    fn default() -> Self {
        Self {
            batch_size: 1000,
            max_queue_size: 10000,
        }
    }
}

impl FtsIndexManager {
    pub fn should_index(&self, queue_size: usize) -> bool {
        queue_size < self.max_queue_size
    }

    pub fn get_batch_size(&self) -> usize {
        self.batch_size
    }
}

pub fn build_fts_query(search_term: &str, fields: &[&str], fuzzy: bool) -> String {
    let mut query = String::new();

    for field in fields {
        if !query.is_empty() {
            query.push_str(" OR ");
        }

        if fuzzy {
            query.push_str(&format!("{}:{}", field, search_term));
        } else {
            query.push_str(&format!("\"{}\"", search_term));
        }
    }

    query
}

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub id: String,
    pub case_id: String,
    pub object_id: String,
    pub object_type: ProvenanceObjectType,
    pub action: ProvenanceAction,
    pub timestamp_utc: u64,
    pub user: String,
    pub session_id: String,
    pub source_evidence_id: Option<String>,
    pub source_volume_id: Option<String>,
    pub source_path: Option<String>,
    pub destination_path: Option<String>,
    pub export_path: Option<String>,
    pub hash_before: Option<String>,
    pub hash_after: Option<String>,
    pub metadata: HashMap<String, String>,
    pub description: String,
}

impl ProvenanceRecord {
    pub fn new(
        case_id: &str,
        object_id: &str,
        object_type: ProvenanceObjectType,
        action: ProvenanceAction,
        user: &str,
        session_id: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            object_id: object_id.to_string(),
            object_type,
            action,
            timestamp_utc: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            user: user.to_string(),
            session_id: session_id.to_string(),
            source_evidence_id: None,
            source_volume_id: None,
            source_path: None,
            destination_path: None,
            export_path: None,
            hash_before: None,
            hash_after: None,
            metadata: HashMap::new(),
            description: String::new(),
        }
    }

    pub fn with_source(mut self, evidence_id: &str, volume_id: &str, path: &str) -> Self {
        self.source_evidence_id = Some(evidence_id.to_string());
        self.source_volume_id = Some(volume_id.to_string());
        self.source_path = Some(path.to_string());
        self
    }

    pub fn with_destination(mut self, path: &str) -> Self {
        self.destination_path = Some(path.to_string());
        self
    }

    pub fn with_export(mut self, path: &str) -> Self {
        self.export_path = Some(path.to_string());
        self
    }

    pub fn with_hashes(mut self, before: &str, after: &str) -> Self {
        self.hash_before = Some(before.to_string());
        self.hash_after = Some(after.to_string());
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProvenanceObjectType {
    File,
    Directory,
    MftEntry,
    RegistryKey,
    RegistryValue,
    Artifact,
    TimelineEvent,
    Process,
    Memory,
    DiskImage,
    Evidence,
    Volume,
    Bookmark,
    Note,
    Exhibit,
    Export,
    Report,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProvenanceAction {
    Created,
    Modified,
    Deleted,
    Copied,
    Moved,
    Renamed,
    Accessed,
    Exported,
    Imported,
    Hashed,
    Verified,
    Tagged,
    Bookmarked,
    Noted,
    Analyzed,
    Processed,
    Extracted,
    Carved,
    Decrypted,
    Parsed,
    Indexed,
    Archived,
    Restored,
    Quarantined,
    Blocked,
    Flagged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustody {
    pub id: String,
    pub case_id: String,
    pub object_id: String,
    pub object_type: ProvenanceObjectType,
    pub entries: Vec<CoCEntry>,
    pub created_at: u64,
    pub modified_at: u64,
    pub is_intact: bool,
}

impl ChainOfCustody {
    pub fn new(case_id: &str, object_id: &str, object_type: ProvenanceObjectType) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            object_id: object_id.to_string(),
            object_type,
            entries: Vec::new(),
            created_at: now,
            modified_at: now,
            is_intact: true,
        }
    }

    pub fn add_entry(&mut self, entry: CoCEntry) {
        if let Some(prev) = self.entries.last() {
            if entry.timestamp_utc < prev.timestamp_utc {
                self.is_intact = false;
            }
        }
        self.entries.push(entry);
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn verify(&self) -> bool {
        for i in 1..self.entries.len() {
            if self.entries[i].timestamp_utc < self.entries[i - 1].timestamp_utc {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoCEntry {
    pub id: String,
    pub timestamp_utc: u64,
    pub action: ProvenanceAction,
    pub user: String,
    pub session_id: String,
    pub details: String,
    pub hash: Option<String>,
    pub location: Option<String>,
}

impl CoCEntry {
    pub fn new(action: ProvenanceAction, user: &str, session_id: &str, details: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp_utc: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            action,
            user: user.to_string(),
            session_id: session_id.to_string(),
            details: details.to_string(),
            hash: None,
            location: None,
        }
    }

    pub fn with_hash(mut self, hash: &str) -> Self {
        self.hash = Some(hash.to_string());
        self
    }

    pub fn with_location(mut self, location: &str) -> Self {
        self.location = Some(location.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceGraph {
    pub nodes: Vec<ProvenanceNode>,
    pub edges: Vec<ProvenanceEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceNode {
    pub id: String,
    pub object_id: String,
    pub object_type: ProvenanceObjectType,
    pub label: String,
    pub timestamp_utc: u64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceEdge {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub action: ProvenanceAction,
    pub timestamp_utc: u64,
    pub label: Option<String>,
}

pub struct ProvenanceTracker {
    case_id: String,
    records: HashMap<String, Vec<ProvenanceRecord>>,
    chains: HashMap<String, ChainOfCustody>,
}

impl ProvenanceTracker {
    pub fn new(case_id: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            records: HashMap::new(),
            chains: HashMap::new(),
        }
    }

    pub fn log_action(&mut self, record: ProvenanceRecord) {
        let object_id = record.object_id.clone();
        self.records.entry(object_id).or_default().push(record);
    }

    pub fn get_object_history(&self, object_id: &str) -> Option<&Vec<ProvenanceRecord>> {
        self.records.get(object_id)
    }

    pub fn get_records_by_action(&self, action: ProvenanceAction) -> Vec<&ProvenanceRecord> {
        self.records
            .values()
            .flatten()
            .filter(|r| r.action == action)
            .collect()
    }

    pub fn get_records_by_type(&self, object_type: ProvenanceObjectType) -> Vec<&ProvenanceRecord> {
        self.records
            .values()
            .flatten()
            .filter(|r| r.object_type == object_type)
            .collect()
    }

    pub fn get_records_by_user(&self, user: &str) -> Vec<&ProvenanceRecord> {
        self.records
            .values()
            .flatten()
            .filter(|r| r.user == user)
            .collect()
    }

    pub fn get_records_in_timeframe(&self, start: u64, end: u64) -> Vec<&ProvenanceRecord> {
        self.records
            .values()
            .flatten()
            .filter(|r| r.timestamp_utc >= start && r.timestamp_utc <= end)
            .collect()
    }

    pub fn init_chain(&mut self, object_id: &str, object_type: ProvenanceObjectType) {
        if !self.chains.contains_key(object_id) {
            let chain = ChainOfCustody::new(&self.case_id, object_id, object_type);
            self.chains.insert(object_id.to_string(), chain);
        }
    }

    pub fn add_to_chain(
        &mut self,
        object_id: &str,
        action: ProvenanceAction,
        user: &str,
        session_id: &str,
        details: &str,
    ) {
        if let Some(chain) = self.chains.get_mut(object_id) {
            let entry = CoCEntry::new(action, user, session_id, details);
            chain.add_entry(entry);
        }
    }

    pub fn get_chain(&self, object_id: &str) -> Option<&ChainOfCustody> {
        self.chains.get(object_id)
    }

    pub fn verify_chain(&self, object_id: &str) -> bool {
        self.chains
            .get(object_id)
            .map(|c| c.verify())
            .unwrap_or(true)
    }

    pub fn build_graph(&self) -> ProvenanceGraph {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        for records in self.records.values() {
            for record in records {
                let node_id = Uuid::new_v4().to_string();
                nodes.push(ProvenanceNode {
                    id: node_id.clone(),
                    object_id: record.object_id.clone(),
                    object_type: record.object_type.clone(),
                    label: format!("{:?}: {}", record.action, record.object_id),
                    timestamp_utc: record.timestamp_utc,
                    metadata: record.metadata.clone(),
                });

                if let Some(ref source) = record.source_path {
                    if let Some(ref dest) = record.destination_path {
                        let edge_id = Uuid::new_v4().to_string();
                        edges.push(ProvenanceEdge {
                            id: edge_id,
                            source_id: source.clone(),
                            target_id: dest.clone(),
                            action: record.action.clone(),
                            timestamp_utc: record.timestamp_utc,
                            label: Some(record.description.clone()),
                        });
                    }
                }
            }
        }

        ProvenanceGraph { nodes, edges }
    }

    pub fn get_all_records(&self) -> Vec<&ProvenanceRecord> {
        self.records.values().flatten().collect()
    }

    pub fn export_chain_report(&self, object_id: &str) -> Option<String> {
        self.chains.get(object_id).map(|chain| {
            let mut report = String::new();
            report.push_str(&format!(
                "Chain of Custody Report for Object: {}\n",
                chain.object_id
            ));
            report.push_str(&format!("Type: {:?}\n", chain.object_type));
            report.push_str(&format!("Intact: {}\n\n", chain.is_intact));

            for entry in &chain.entries {
                report.push_str(&format!(
                    "[{}] {:?} - {} by {}\n",
                    entry.timestamp_utc, entry.action, entry.details, entry.user
                ));
                if let Some(ref hash) = entry.hash {
                    report.push_str(&format!("  Hash: {}\n", hash));
                }
                if let Some(ref loc) = entry.location {
                    report.push_str(&format!("  Location: {}\n", loc));
                }
            }
            report
        })
    }
}

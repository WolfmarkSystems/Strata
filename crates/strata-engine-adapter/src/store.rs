//! In-process registry of opened evidence images. Each `parse_evidence` call
//! produces a stable `evidence_id` that subsequent commands look up here.

use crate::types::AdapterError;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use strata_fs::container::EvidenceSource;

/// Snapshot of file metadata cached after the first directory walk so the UI
/// can request hex/text/metadata by stable file id without a re-walk.
#[derive(Debug, Clone)]
pub struct CachedFile {
    pub id: String,
    pub vfs_path: PathBuf,
    pub name: String,
    pub extension: String,
    pub size: u64,
    pub modified: String,
    pub created: String,
    pub accessed: String,
    pub is_dir: bool,
    pub parent_node_id: String,
    pub mft_entry: Option<u64>,
    pub inode: Option<u64>,
}

/// Snapshot of a tree node so the UI can list children without re-walking the
/// volume each time.
#[derive(Debug, Clone)]
pub struct CachedNode {
    pub id: String,
    pub name: String,
    pub node_type: String, // "evidence" | "volume" | "folder"
    pub vfs_path: PathBuf,
    pub volume_index: Option<usize>,
    pub parent_id: Option<String>,
    pub depth: u32,
    pub child_ids: Vec<String>,
    pub children_loaded: bool,
}

/// All state owned by a single open evidence image.
pub struct OpenEvidence {
    pub id: String,
    pub source: EvidenceSource,
    pub nodes: HashMap<String, CachedNode>,
    pub files: HashMap<String, CachedFile>,
    pub root_node_ids: Vec<String>,
}

impl OpenEvidence {
    pub fn new(id: String, source: EvidenceSource) -> Self {
        Self {
            id,
            source,
            nodes: HashMap::new(),
            files: HashMap::new(),
            root_node_ids: Vec::new(),
        }
    }
}

/// Process-wide singleton: id → open evidence.
pub static EVIDENCE_STORE: Lazy<Mutex<HashMap<String, Arc<Mutex<OpenEvidence>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Insert a freshly opened evidence into the store and return its id.
pub fn insert_evidence(id: String, source: EvidenceSource) -> Arc<Mutex<OpenEvidence>> {
    let entry = Arc::new(Mutex::new(OpenEvidence::new(id.clone(), source)));
    EVIDENCE_STORE
        .lock()
        .expect("evidence store poisoned")
        .insert(id, entry.clone());
    entry
}

/// Look up an open evidence by id.
pub fn get_evidence(id: &str) -> Result<Arc<Mutex<OpenEvidence>>, AdapterError> {
    let store = EVIDENCE_STORE.lock().expect("evidence store poisoned");
    store
        .get(id)
        .cloned()
        .ok_or_else(|| AdapterError::EvidenceNotFound(id.to_string()))
}

/// Drop an evidence from the store (frees its VFS handle).
pub fn drop_evidence(id: &str) -> bool {
    EVIDENCE_STORE
        .lock()
        .expect("evidence store poisoned")
        .remove(id)
        .is_some()
}

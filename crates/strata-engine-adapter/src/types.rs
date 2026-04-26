//! Types exposed by the adapter. These are deliberately simple, JSON-friendly,
//! and free of any direct references to strata-fs/strata-core internal types so
//! the consumer (Tauri desktop app) can serialize them straight to the UI.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvidenceInfo {
    pub id: String,
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub size_display: String,
    pub format: String,
    pub file_count: u64,
    pub hash_md5: Option<String>,
    pub hash_sha1: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TreeNode {
    pub id: String,
    pub name: String,
    pub node_type: String,
    pub count: u64,
    pub file_count: u64,
    pub folder_count: u64,
    pub has_children: bool,
    pub parent_id: Option<String>,
    pub depth: u32,
    pub is_deleted: bool,
    pub is_flagged: bool,
    pub is_suspicious: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileEntry {
    pub id: String,
    pub name: String,
    pub extension: String,
    pub size: u64,
    pub size_display: String,
    pub modified: String,
    pub created: String,
    pub accessed: String,
    pub full_path: String,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub is_deleted: bool,
    pub is_suspicious: bool,
    pub is_flagged: bool,
    pub known_good: bool,
    pub category: String,
    pub inode: Option<u64>,
    pub mft_entry: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvidenceIntegrity {
    pub sha256: String,
    pub computed_at: i64,
    pub file_size_bytes: u64,
    pub verified: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HexLine {
    pub offset: String,
    pub hex: String,
    pub ascii: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HexData {
    pub lines: Vec<HexLine>,
    pub total_size: u64,
    pub offset: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArtifactCategoryInfo {
    pub name: String,
    pub icon: String,
    pub count: u64,
    pub color: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PluginArtifact {
    pub id: String,
    pub category: String,
    pub name: String,
    pub value: String,
    pub timestamp: Option<String>,
    pub source_file: String,
    pub source_path: String,
    pub forensic_value: String,
    pub mitre_technique: Option<String>,
    pub mitre_name: Option<String>,
    pub plugin: String,
    pub raw_data: Option<String>,
    pub is_advisory: bool,
    pub advisory_notice: Option<String>,
    pub confidence_score: f32,
    pub confidence_basis: String,
}

/// Sprint-11 P1 — one row inside a `MessageThread`. A flattened, IPC-
/// friendly shape designed for the conversation view: timestamp +
/// direction + body + service, plus a back-pointer to the original
/// `PluginArtifact.id` so the UI can still drill into raw fields.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ThreadMessage {
    pub artifact_id: String,
    pub timestamp: Option<String>,
    /// `"inbound"` / `"outbound"` / `"unknown"`.
    pub direction: String,
    /// `"iMessage"`, `"SMS"`, `"WhatsApp"`, …
    pub service: String,
    /// Plain-text body when available — pulled from the artifact's
    /// `body` field with `value` as the fallback.
    pub body: String,
    pub source_path: String,
}

/// Sprint-11 P1 — one conversation: a participant + the messages
/// exchanged with them, sorted chronologically. Returned by
/// `get_artifacts_by_thread`. Threads with `participant.is_empty()`
/// represent ungrouped artifacts and are emitted last so the UI can
/// fall back to the flat list for non-message data.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MessageThread {
    pub thread_id: String,
    pub participant: String,
    pub service: String,
    pub messages: Vec<ThreadMessage>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IocQuery {
    pub indicators: Vec<String>,
    pub evidence_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IocMatch {
    pub indicator: String,
    pub artifact: PluginArtifact,
    pub match_field: String,
    pub confidence: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct EngineStats {
    pub files: u64,
    pub suspicious: u64,
    pub flagged: u64,
    pub carved: u64,
    pub hashed: u64,
    pub known_good: u64,
    pub unknown: u64,
    pub artifacts: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HashResult {
    pub file_id: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HashSetInfo {
    pub name: String,
    pub description: String,
    pub hash_count: usize,
    pub imported_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HashSetStats {
    pub set_count: usize,
    pub hash_count: usize,
    pub known_good: u64,
    pub unknown: u64,
}

pub type AdapterResult<T> = Result<T, AdapterError>;

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("Evidence not found: {0}")]
    EvidenceNotFound(String),
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Engine error: {0}")]
    EngineError(String),
    /// Sprint-11 P2 — generic not-found used by `navigate_to_path`
    /// when the supplied source path is not part of the evidence
    /// tree. Distinct from `FileNotFound` (which means a file the
    /// caller already pointed at could not be read) — `NotFound` is
    /// the lookup-failed-cleanly case the UI surfaces as a toast.
    #[error("Not found: {0}")]
    NotFound(String),
}

/// Format raw byte counts for display ("9.8 GB", "44 MB", "2.4 KB", "812 B").
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

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
    pub category: String,
    pub inode: Option<u64>,
    pub mft_entry: Option<u64>,
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
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct EngineStats {
    pub files: u64,
    pub suspicious: u64,
    pub flagged: u64,
    pub carved: u64,
    pub hashed: u64,
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

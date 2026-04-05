use serde::{Deserialize, Serialize};

/// Structured evidence context passed from Tree or entered manually.
/// Injected into the LLM system prompt so the model has forensic
/// context without the examiner having to re-type it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForgeContext {
    /// Full path of the file under examination.
    pub file_path: Option<String>,
    /// SHA-256 hash of the file.
    pub file_hash_sha256: Option<String>,
    /// File size in bytes.
    pub file_size: Option<u64>,
    /// Category assigned by the indexer (e.g. "Executable", "Document").
    pub file_category: Option<String>,
    /// Registry key/value path if examining a registry artifact.
    pub registry_path: Option<String>,
    /// Command line string if examining process execution.
    pub command_line: Option<String>,
    /// List of IOCs: hashes, IPs, domains, file paths.
    #[serde(default)]
    pub ioc_list: Vec<String>,
    /// Case name from Tree's active case.
    pub case_name: Option<String>,
    /// Timestamps associated with the artifact.
    pub timestamps: Option<ArtifactTimestamps>,
}

/// UTC timestamps for an artifact under examination.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactTimestamps {
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
}

impl ForgeContext {
    /// Returns true if this context has no meaningful data.
    pub fn is_empty(&self) -> bool {
        self.file_path.is_none()
            && self.file_hash_sha256.is_none()
            && self.file_category.is_none()
            && self.registry_path.is_none()
            && self.command_line.is_none()
            && self.ioc_list.is_empty()
            && self.case_name.is_none()
    }

    /// Build a human-readable context block for injection into the system prompt.
    pub fn to_prompt_block(&self) -> String {
        if self.is_empty() {
            return String::new();
        }

        let mut lines = Vec::new();
        lines.push("Current evidence context:".to_string());

        if let Some(ref p) = self.file_path {
            lines.push(format!("  File: {}", p));
        }
        if let Some(ref h) = self.file_hash_sha256 {
            lines.push(format!("  SHA-256: {}", h));
        }
        if let Some(s) = self.file_size {
            lines.push(format!("  Size: {} bytes", s));
        }
        if let Some(ref c) = self.file_category {
            lines.push(format!("  Category: {}", c));
        }
        if let Some(ref r) = self.registry_path {
            lines.push(format!("  Registry: {}", r));
        }
        if let Some(ref cmd) = self.command_line {
            lines.push(format!("  Command: {}", cmd));
        }
        if !self.ioc_list.is_empty() {
            lines.push(format!("  IOCs: {}", self.ioc_list.join(", ")));
        }
        if let Some(ref cn) = self.case_name {
            lines.push(format!("  Case: {}", cn));
        }
        if let Some(ref ts) = self.timestamps {
            if let Some(ref c) = ts.created {
                lines.push(format!("  Created: {}", c));
            }
            if let Some(ref m) = ts.modified {
                lines.push(format!("  Modified: {}", m));
            }
            if let Some(ref a) = ts.accessed {
                lines.push(format!("  Accessed: {}", a));
            }
        }

        lines.join("\n")
    }
}

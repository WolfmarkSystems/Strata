//! Selective re-scan with content-hash deduplication (WF-12).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeMode {
    Replace,
    Append,
    Deduplicate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RescanRequest {
    pub image_path: PathBuf,
    pub plugins: Vec<String>,
    pub merge_mode: MergeMode,
    pub output_path: PathBuf,
}

/// Content hash used for deduplication.
pub fn content_hash(a: &Artifact) -> String {
    let file_type = a
        .data
        .get("file_type")
        .cloned()
        .unwrap_or_else(|| a.category.clone());
    let description = a
        .data
        .get("title")
        .cloned()
        .or_else(|| a.data.get("detail").cloned())
        .unwrap_or_default();
    let ts_us = a
        .timestamp
        .map(|s| (s as i64).saturating_mul(1_000_000))
        .unwrap_or(0);
    let payload = format!(
        "{}|{}|{}|{}",
        file_type, a.source, ts_us, description
    );
    let digest = Sha256::digest(payload.as_bytes());
    hex_of(&digest)
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Merge new plugin results into existing artifact set according to
/// the request's mode. Plugin scope is determined by the `plugin`
/// field on existing artifacts; those not tagged with a plugin in the
/// request's list are always preserved.
pub fn merge_rescan(
    existing: Vec<Artifact>,
    new_from_plugins: Vec<Artifact>,
    request: &RescanRequest,
) -> Vec<Artifact> {
    let target_plugins: HashSet<String> = request.plugins.iter().cloned().collect();
    let is_target = |art: &Artifact| -> bool {
        if target_plugins.is_empty() {
            return true;
        }
        art.data
            .get("plugin")
            .map(|p| target_plugins.contains(p))
            .unwrap_or(false)
    };
    match request.merge_mode {
        MergeMode::Replace => {
            let mut out: Vec<Artifact> =
                existing.into_iter().filter(|a| !is_target(a)).collect();
            out.extend(new_from_plugins);
            out
        }
        MergeMode::Append => {
            let mut out = existing;
            out.extend(new_from_plugins);
            out
        }
        MergeMode::Deduplicate => {
            let mut seen: HashSet<String> =
                existing.iter().map(content_hash).collect();
            let mut out = existing;
            for a in new_from_plugins {
                let h = content_hash(&a);
                if seen.insert(h) {
                    out.push(a);
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(plugin: &str, file_type: &str, title: &str) -> Artifact {
        let mut a = Artifact::new(file_type, "/evidence/x");
        a.add_field("plugin", plugin);
        a.add_field("file_type", file_type);
        a.add_field("title", title);
        a
    }

    fn req(plugins: Vec<&str>, mode: MergeMode) -> RescanRequest {
        RescanRequest {
            image_path: PathBuf::from("/evidence/img.E01"),
            plugins: plugins.into_iter().map(String::from).collect(),
            merge_mode: mode,
            output_path: PathBuf::from("/tmp/out.json"),
        }
    }

    #[test]
    fn replace_drops_target_plugin_artifacts() {
        let existing = vec![
            art("phantom", "Prefetch", "A"),
            art("mactrace", "Biome", "B"),
        ];
        let fresh = vec![art("phantom", "Prefetch", "A2")];
        let merged = merge_rescan(existing, fresh, &req(vec!["phantom"], MergeMode::Replace));
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().any(|a| a.data.get("title") == Some(&"A2".to_string())));
        assert!(merged.iter().any(|a| a.data.get("title") == Some(&"B".to_string())));
    }

    #[test]
    fn append_adds_duplicates() {
        let existing = vec![art("phantom", "Prefetch", "A")];
        let fresh = vec![art("phantom", "Prefetch", "A")];
        let merged = merge_rescan(existing, fresh, &req(vec!["phantom"], MergeMode::Append));
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn deduplicate_collapses_identical_content() {
        let existing = vec![art("phantom", "Prefetch", "A")];
        let fresh = vec![
            art("phantom", "Prefetch", "A"),
            art("phantom", "Prefetch", "B"),
        ];
        let merged = merge_rescan(existing, fresh, &req(vec!["phantom"], MergeMode::Deduplicate));
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn content_hash_is_stable_and_sensitive_to_fields() {
        let a = art("phantom", "Prefetch", "Same");
        let b = art("phantom", "Prefetch", "Same");
        assert_eq!(content_hash(&a), content_hash(&b));
        let c = art("phantom", "Prefetch", "Different");
        assert_ne!(content_hash(&a), content_hash(&c));
    }

    #[test]
    fn empty_plugin_list_targets_everything() {
        let existing = vec![art("phantom", "X", "1")];
        let fresh = vec![art("phantom", "X", "2")];
        let merged = merge_rescan(existing, fresh, &req(vec![], MergeMode::Replace));
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].data.get("title"), Some(&"2".to_string()));
    }
}

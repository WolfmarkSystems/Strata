//! WIN25H2-1 — Windows 11 24H2/25H2 AI Actions in File Explorer.
//!
//! Right-click -> AI Actions exposes Visual Search, Blur Background,
//! Generative Erase, and Remove Background on JPG/PNG files directly
//! from Explorer. Each invocation leaves registry, event-log, and
//! AppData traces. This module defines the canonical record
//! (`WindowsAIAction`) and the helpers used by the chronicle plugin
//! to reconstruct events from those three sources.
//!
//! Wiring to actual hives / .evtx / AppData paths lives in the
//! plugin's dispatch layer; this module owns the record shape and
//! the parsing of registry subkey names that encode action types +
//! timestamps.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AIActionType {
    VisualSearch,
    BlurBackground,
    EraseObjects,
    RemoveBackground,
    Other,
}

impl AIActionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VisualSearch => "VisualSearch",
            Self::BlurBackground => "BlurBackground",
            Self::EraseObjects => "EraseObjects",
            Self::RemoveBackground => "RemoveBackground",
            Self::Other => "Other",
        }
    }
    /// Is this action a manipulation that alters the source image?
    /// Used to flag `is_suspicious=true` when the action is likely
    /// counter-surveillance / evidence-tampering adjacent.
    pub fn is_manipulation(&self) -> bool {
        matches!(self, Self::BlurBackground | Self::EraseObjects | Self::RemoveBackground)
    }
}

pub fn parse_action_name(raw: &str) -> AIActionType {
    match raw.to_ascii_lowercase().trim() {
        "visualsearch" | "visual_search" | "bingvisualsearch" => AIActionType::VisualSearch,
        "blurbackground" | "blur_background" => AIActionType::BlurBackground,
        "eraseobjects" | "erase_objects" | "generativeerase" => AIActionType::EraseObjects,
        "removebackground" | "remove_background" => AIActionType::RemoveBackground,
        _ => AIActionType::Other,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowsAIAction {
    pub action_type: AIActionType,
    pub timestamp: DateTime<Utc>,
    pub source_file_path: Option<String>,
    pub source_file_hash: Option<String>,
    pub result_file_path: Option<String>,
    pub user_context: String,
}

/// Convert a Windows FILETIME (100-ns ticks since 1601-01-01) to UTC.
pub fn filetime_to_utc(filetime: u64) -> Option<DateTime<Utc>> {
    const WINDOWS_TICK: i64 = 10_000_000;
    const SEC_TO_UNIX_EPOCH: i64 = 11_644_473_600;
    let secs = (filetime as i64 / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH;
    if secs < 0 {
        return None;
    }
    Utc.timestamp_opt(secs, 0).single()
}

/// Build a `WindowsAIAction` from a canonical registry-key tuple —
/// the subkey name encodes the action, the `LastInvoked` value is a
/// FILETIME, and `LastPath` / `LastHash` may be present for some
/// actions.
pub fn from_registry_entry(
    subkey_name: &str,
    last_invoked_filetime: u64,
    last_path: Option<&str>,
    last_hash: Option<&str>,
    user_context: &str,
) -> Option<WindowsAIAction> {
    let action_type = parse_action_name(subkey_name);
    if action_type == AIActionType::Other {
        return None;
    }
    let timestamp = filetime_to_utc(last_invoked_filetime)?;
    Some(WindowsAIAction {
        action_type,
        timestamp,
        source_file_path: last_path.map(|s| s.to_string()),
        source_file_hash: last_hash.map(|s| s.to_string()),
        result_file_path: None,
        user_context: user_context.to_string(),
    })
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_action_names() {
        assert_eq!(parse_action_name("VisualSearch"), AIActionType::VisualSearch);
        assert_eq!(parse_action_name("blur_background"), AIActionType::BlurBackground);
        assert_eq!(parse_action_name("generativeerase"), AIActionType::EraseObjects);
        assert_eq!(parse_action_name("RemoveBackground"), AIActionType::RemoveBackground);
        assert_eq!(parse_action_name("Unknown"), AIActionType::Other);
    }

    #[test]
    fn manipulation_flag_matches_spec() {
        assert!(AIActionType::BlurBackground.is_manipulation());
        assert!(AIActionType::EraseObjects.is_manipulation());
        assert!(AIActionType::RemoveBackground.is_manipulation());
        assert!(!AIActionType::VisualSearch.is_manipulation());
    }

    #[test]
    fn filetime_round_trip() {
        // 2024-01-01T00:00:00Z = unix 1704067200. FILETIME is that in
        // 100ns ticks since 1601-01-01, so (1704067200 + 11644473600)
        // * 10^7 = 133_485_408_000_000_000.
        let ft = 133_485_408_000_000_000u64;
        let ts = filetime_to_utc(ft).expect("parsed");
        assert_eq!(ts.timestamp(), 1_704_067_200);
    }

    #[test]
    fn from_registry_entry_builds_record() {
        let r = from_registry_entry(
            "BlurBackground",
            133_485_408_000_000_000,
            Some("C:\\Users\\alice\\photo.jpg"),
            Some("deadbeef"),
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AIActions",
        )
        .expect("built");
        assert_eq!(r.action_type, AIActionType::BlurBackground);
        assert_eq!(r.source_file_path.as_deref(), Some("C:\\Users\\alice\\photo.jpg"));
    }

    #[test]
    fn from_registry_entry_rejects_unknown_subkey() {
        let r = from_registry_entry("WeirdAction", 133_484_544_000_000_000, None, None, "");
        assert!(r.is_none());
    }
}
